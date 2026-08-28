from __future__ import annotations

import argparse,json
from pathlib import Path

from mac_audit_agent.launch_agent import default_monitor_db_path

from .attack import RCEAttackValidator
from .config import load_rce_config
from .injection_analytics import TEMPLATES
from .repository import RCERepository


def _parser()->argparse.ArgumentParser:
    p=argparse.ArgumentParser(prog="msaa process-injection",description="macOS process-injection assurance and research")
    p.add_argument("--db",type=Path,default=default_monitor_db_path("system"));p.add_argument("--config",type=Path,default=Path("/Library/Application Support/MacAuditAgent/config/rce-monitor.json"))
    sub=p.add_subparsers(dest="command",required=True)
    for name in ("status","health","sensors-status","rules-validate","config-validate","research-list","benign-context-list","suppressions-list"):sub.add_parser(name)
    for name in ("events-show","events-timeline","events-graph","investigate"):q=sub.add_parser(name);q.add_argument("event_id")
    q=sub.add_parser("events-list");q.add_argument("--limit",type=int,default=100)
    q=sub.add_parser("disposition");q.add_argument("event_id");q.add_argument("disposition");q.add_argument("--reviewer",required=True);q.add_argument("--reason",required=True);q.add_argument("--case",required=True)
    q=sub.add_parser("research-show");q.add_argument("candidate_id")
    q=sub.add_parser("research-compare");q.add_argument("candidate_id")
    q=sub.add_parser("benign-context-create");q.add_argument("record",type=Path)
    q=sub.add_parser("suppressions-create");q.add_argument("record",type=Path);q.add_argument("--elevated",action="store_true")
    return p


def _authorized(repo:RCERepository,config)->bool:return repo.management_authorized(config.allowed_management_uids)


def main(argv:list[str]|None=None)->int:
    args=_parser().parse_args(argv);repo=RCERepository(args.db);config=load_rce_config(args.config)
    if args.command in {"status","health"}:print(json.dumps(repo.status(),indent=2,sort_keys=True));return 0
    if args.command=="sensors-status":
        attack=RCEAttackValidator(Path(config.attack_data_path) if config.attack_data_path else None,freshness_hours=config.attack_freshness_hours)
        print(json.dumps({"process":"DEGRADED_POLLING","thread":"UNAVAILABLE_NO_ENTITLED_SENSOR","memory":"SNAPSHOT_ONLY","module":"SNAPSHOT_ONLY","cross_process_access":"UNAVAILABLE_NO_ENTITLED_SENSOR","attack_data":attack.status(),"no_telemetry_is_not_no_candidates":True},indent=2,sort_keys=True));return 0
    if args.command=="config-validate":print(json.dumps({"valid":True,"schema_version":config.schema_version,"tier2_enabled":config.tier2_memory_capture_enabled},indent=2));return 0
    if args.command=="rules-validate":
        failures=[]
        for rule in TEMPLATES:
            if not rule.required or not rule.version or not rule.required_sensors or not rule.attack_external_id:failures.append(rule.rule_id)
        print(json.dumps({"valid":not failures,"rule_count":len(TEMPLATES),"failures":failures,"promotion":"HUMAN_REVIEW_AND_REGRESSION_TESTS_REQUIRED"},indent=2));return 0 if not failures else 2
    if args.command=="events-list":print(json.dumps(repo.list_events(args.limit),indent=2,sort_keys=True));return 0
    if args.command in {"events-show","events-timeline","events-graph","investigate"}:
        event=repo.event_detail(args.event_id)
        if not event:print(json.dumps({"error":"event not found"}));return 2
        behavioral=dict(event.get("injection_analysis",{}).get("behavioral_analysis",{}));graph=dict(behavioral.get("graph",{}))
        if args.command=="events-timeline":payload=sorted(graph.get("edges",[]),key=lambda item:item.get("observed_at",""))
        elif args.command=="events-graph":payload=graph
        elif args.command=="investigate":payload={"event_id":args.event_id,"review_state":"INVESTIGATING","observed_behavior":event.get("observed_behavior",[]),"source_process":event.get("source_process",{}),"target_process":event.get("target_process",{}),"primitives":behavioral.get("normalized_primitives",[]),"known_technique":behavioral.get("nearest_known_technique",{}),"variant":behavioral.get("variant_analysis",{}),"novelty":behavioral.get("novelty_analysis",{}),"footprints":behavioral.get("footprint_similarities",[]),"possible_benign":behavioral.get("possible_benign_explanations",[]),"contradictory":event.get("contradictory_signals",[]),"missing":event.get("unknowns",[]),"sensor_gaps":behavioral.get("telemetry_gaps",[]),"evidence_references":event.get("evidence_references",[]),"recommended_validation":event.get("recommended_validation",[]),"review_history":event.get("disposition_history",[]),"suppression_status":event.get("suppression_status","not_suppressed")}
        else:payload=event
        print(json.dumps(payload,indent=2,sort_keys=True));return 0
    if args.command=="disposition":
        try:repo.disposition(args.event_id,args.disposition,reviewer=args.reviewer,reason=args.reason,case_reference=args.case,authorized=_authorized(repo,config))
        except (PermissionError,ValueError,KeyError) as exc:print(json.dumps({"error":str(exc)}));return 2
        print(json.dumps({"updated":True,"event_id":args.event_id}));return 0
    if args.command=="research-list":print(json.dumps(repo.list_research(),indent=2,sort_keys=True));return 0
    if args.command in {"research-show","research-compare"}:
        row=repo.conn.execute("SELECT * FROM process_injection_research WHERE candidate_id=?",(args.candidate_id,)).fetchone()
        if not row:print(json.dumps({"error":"research candidate not found"}));return 2
        payload=dict(row);payload["analysis"]=json.loads(payload.pop("payload_json"));print(json.dumps(payload,indent=2,sort_keys=True));return 0
    if args.command=="benign-context-list":print(json.dumps(repo.list_benign_contexts(),indent=2,sort_keys=True));return 0
    if args.command=="benign-context-create":
        if args.record.stat().st_size>1_048_576:print(json.dumps({"error":"record too large"}));return 2
        try:record=json.loads(args.record.read_text(encoding="utf-8"));context_id=repo.create_benign_context(record,authorized=_authorized(repo,config))
        except (OSError,ValueError,PermissionError,json.JSONDecodeError) as exc:print(json.dumps({"error":type(exc).__name__}));return 2
        print(json.dumps({"catalog_record_id":context_id}));return 0
    if args.command=="suppressions-list":
        rows=[dict(row) for row in repo.conn.execute("SELECT suppression_id,owner_reference,reason,matcher_json,created_at,expires_at,enabled,broad,occurrence_count,last_match_at FROM rce_suppressions ORDER BY created_at DESC").fetchall()];print(json.dumps(rows,indent=2,sort_keys=True));return 0
    if args.command=="suppressions-create":
        try:
            if args.record.stat().st_size>1_048_576:raise ValueError("record too large")
            record=json.loads(args.record.read_text(encoding="utf-8"));suppression_id=repo.create_suppression(dict(record.get("matcher",{})),owner=str(record.get("owner","")),reason=str(record.get("reason","")),expires_at=str(record.get("expires_at","")),authorized=_authorized(repo,config),elevated=bool(args.elevated),reviewer=str(record.get("reviewer","")),rule_version=str(record.get("rule_version","1.0")),host_scope=str(record.get("host_scope","")))
        except (OSError,ValueError,PermissionError,json.JSONDecodeError) as exc:print(json.dumps({"error":str(exc)}));return 2
        print(json.dumps({"suppression_id":suppression_id}));return 0
    return 2


if __name__=="__main__":raise SystemExit(main())
