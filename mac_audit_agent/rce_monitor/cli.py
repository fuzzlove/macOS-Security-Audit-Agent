from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from mac_audit_agent.launch_agent import default_monitor_db_path

from .config import load_rce_config
from .cve import CVECorrelator, LocalJSONCVEProvider
from .repository import RCERepository
from .injection_evidence import InjectionEvidenceCollector
from mac_audit_agent.secure_evidence_collection import EvidenceRepository


def parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(prog="msaa rce-monitor",description="Local RCE monitor management and review")
    p.add_argument("--db",type=Path,default=default_monitor_db_path("system")); p.add_argument("--config",type=Path,default=Path("/Library/Application Support/MacAuditAgent/config/rce-monitor.json"))
    sub=p.add_subparsers(dest="command",required=True)
    sub.add_parser("status"); sub.add_parser("health"); sub.add_parser("config-validate")
    events=sub.add_parser("events-list"); events.add_argument("--limit",type=int,default=100)
    show=sub.add_parser("events-show"); show.add_argument("event_id")
    disp=sub.add_parser("events-disposition"); disp.add_argument("event_id"); disp.add_argument("disposition"); disp.add_argument("--reviewer",required=True); disp.add_argument("--reason",required=True); disp.add_argument("--case",default="")
    cve=sub.add_parser("cve-show"); cve.add_argument("cve_id")
    imp=sub.add_parser("cve-import"); imp.add_argument("path",type=Path)
    sub.add_parser("verify-chain")
    demo=sub.add_parser("demo-suspected-rce"); demo.add_argument("--notify",action="store_true",help="Show one clearly labeled synthetic RCE visible alert in the logged-in GUI session")
    plan=sub.add_parser("injection-plan"); plan.add_argument("event_id")
    snapshot=sub.add_parser("injection-snapshot"); snapshot.add_argument("--case-id",required=True); snapshot.add_argument("--analyst",required=True); snapshot.add_argument("--source-pid",type=int,required=True); snapshot.add_argument("--source-path",type=Path,required=True); snapshot.add_argument("--target-pid",type=int,required=True); snapshot.add_argument("--target-path",type=Path,required=True); snapshot.add_argument("--evidence-root",type=Path,default=Path("/Library/Application Support/MacAuditAgent/evidence")); snapshot.add_argument("--evidence-db",type=Path,default=Path("/Library/Application Support/MacAuditAgent/evidence.sqlite3"))
    return p


def main(argv:list[str]|None=None)->int:
    args=parser().parse_args(argv); repo=RCERepository(args.db)
    if args.command in {"status","health"}: print(json.dumps(repo.status(),indent=2,sort_keys=True)); return 0
    if args.command=="config-validate":
        try: config=load_rce_config(args.config)
        except Exception as exc: print(json.dumps({"valid":False,"error":type(exc).__name__})); return 2
        print(json.dumps({"valid":True,"schema_version":config.schema_version},indent=2)); return 0
    if args.command=="events-list": print(json.dumps(repo.list_events(args.limit),indent=2,sort_keys=True)); return 0
    if args.command=="events-show":
        result=repo.event_detail(args.event_id)
        if result is None: print(json.dumps({"error":"event not found"})); return 2
        print(json.dumps(result,indent=2,sort_keys=True)); return 0
    if args.command=="events-disposition":
        try: repo.disposition(args.event_id,args.disposition,reviewer=args.reviewer,reason=args.reason,case_reference=args.case,authorized=repo.management_authorized(load_rce_config(args.config).allowed_management_uids))
        except (PermissionError,ValueError,KeyError) as exc: print(json.dumps({"error":str(exc)})); return 2
        print(json.dumps({"updated":True,"event_id":args.event_id})); return 0
    if args.command=="cve-show":
        result=CVECorrelator(repo).get(args.cve_id)
        if result is None: print(json.dumps({"verified":False,"error":"CVE absent from approved local store"})); return 2
        print(json.dumps(result,indent=2,sort_keys=True)); return 0
    if args.command=="cve-import":
        if not repo.management_authorized(load_rce_config(args.config).allowed_management_uids): print(json.dumps({"error":"local management authorization required"})); return 2
        try: count=LocalJSONCVEProvider().import_file(args.path,repo)
        except (OSError,ValueError,json.JSONDecodeError) as exc: print(json.dumps({"error":type(exc).__name__})); return 2
        print(json.dumps({"imported":count})); return 0
    if args.command=="verify-chain":
        valid,detail=repo.verify_chain(); print(json.dumps({"valid":valid,"detail":detail})); return 0 if valid else 3
    if args.command=="demo-suspected-rce":
        from .service import RCEMonitorService
        from .synthetic import suspected_rce_demo

        service=RCEMonitorService(repo,args.config,executor=lambda *unused_args,**unused_kwargs: None)
        finding_objects=[finding for event in suspected_rce_demo() if (finding:=service.ingest(event))]
        notification={"requested":bool(args.notify),"delivered":False}
        if args.notify and finding_objects:
            from mac_audit_agent.models import BackgroundMonitorEvent
            from mac_audit_agent.notification_manager import NotificationManager
            from mac_audit_agent.storage import AuditDatabase

            final=next((item for item in reversed(finding_objects) if item.event_type=="SUSPECTED_REMOTE_CODE_EXECUTION"),finding_objects[-1])
            audit=AuditDatabase(args.db,args.db.parent/"mac_audit_agent_logs")
            visible=BackgroundMonitorEvent(
                event_id=f"monitor-{final.event_id}",timestamp=final.observed_at,event_type="execution_evidence_detected",
                severity="high",source="rce_synthetic_demonstration",process_name=str(final.process.get("name") or Path(str(final.process.get("executable", ""))).name),
                pid=final.process.get("pid") if isinstance(final.process.get("pid"),int) else None,
                evidence="SYNTHETIC TEST — Suspected Remote Code Execution: "+(final.why_flagged or "; ".join(final.observed_behavior)),
                confidence="high",recommendation="No containment action is required. Open Host IDS → Suspected RCE to inspect this benign demonstration.",
                simulated=True,rule_id="RCE-DEMO-001",rule_name="Synthetic suspected RCE demonstration",trigger_source="rce_synthetic_demonstration",
                normalized_signal=final.rce_subtype,correlation_id=final.correlation_id,duplicate_group_key=f"rce-demo:{final.event_id}",
                metadata_json=json.dumps({"rce_event_id":final.event_id,"rce_classification":final.rce_classification,"rce_subtype":final.rce_subtype,"confidence_score":final.confidence_score,"synthetic":True},sort_keys=True),
            )
            stored=audit.record_background_monitor_event(visible,dedupe_window_seconds=0)
            delivered=NotificationManager(audit).show_visible_security_alert(visible,reason="synthetic_rce_demonstration",force=True)
            audit.update_monitor_event_notification(visible.event_id,notification_sent=bool(delivered),notification_error="" if delivered else "visible alert overlay delivery failed",notification_returncode=0 if delivered else 1,notification_decision="sent" if delivered else "overlay_failed",notification_reason="synthetic_rce_demonstration",cooldown_remaining_seconds=0,popup_allowed=True,visible_alert_shown=bool(delivered),alert_style=getattr(visible,"alert_style",""),cooldown_suppressed=False,last_suppression_reason="")
            notification={"requested":True,"stored":bool(stored),"delivered":bool(delivered),"event_id":visible.event_id}
        findings=[finding.to_dict() for finding in finding_objects]
        print(json.dumps({"fixture":"benign-synthetic-rce-sequence","weaponized_code":False,"notification":notification,"findings":findings},indent=2,sort_keys=True))
        return 0
    if args.command=="injection-plan":
        detail=repo.event_detail(args.event_id)
        if not detail: print(json.dumps({"error":"event not found"})); return 2
        analysis=dict(detail.get("injection_analysis",{}))
        if not analysis: print(json.dumps({"error":"event has no process-injection assessment"})); return 2
        print(json.dumps(analysis,indent=2,sort_keys=True)); return 0
    if args.command=="injection-snapshot":
        config=load_rce_config(args.config)
        if not repo.management_authorized(config.allowed_management_uids): print(json.dumps({"error":"local management authorization required"})); return 2
        source_path=args.source_path.expanduser().resolve(strict=False); target_path=args.target_path.expanduser().resolve(strict=False)
        if not source_path.is_absolute() or not target_path.is_absolute(): print(json.dumps({"error":"absolute normalized process paths are required"})); return 2
        try:
            evidence=EvidenceRepository(args.evidence_root.expanduser(),args.evidence_db.expanduser())
            result=InjectionEvidenceCollector(evidence).capture(args.case_id,args.analyst,source_process={"pid":args.source_pid,"executable":str(source_path)},target_process={"pid":args.target_pid,"executable":str(target_path)})
        except Exception as exc:
            print(json.dumps({"error":type(exc).__name__,"message":"injection snapshot failed; review protected local logs"})); return 2
        print(json.dumps(result,indent=2,sort_keys=True)); return 0
    return 2


if __name__=="__main__": raise SystemExit(main())
