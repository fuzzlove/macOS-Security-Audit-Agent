from __future__ import annotations

import argparse
import json
import resource
import statistics
import tempfile
import time
from pathlib import Path

from mac_audit_agent.alerts.resilient_pipeline import ResilientAlertPipeline
from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.storage import AuditDatabase


def main() -> int:
    parser=argparse.ArgumentParser(description="Repeatable local MSAA alert-pipeline benchmark; results are environment-specific.")
    parser.add_argument("--events",type=int,default=10_000); parser.add_argument("--output",type=Path); args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="msaa-alert-benchmark-") as root:
        db=AuditDatabase(Path(root)/"benchmark.sqlite3"); pipeline=ResilientAlertPipeline(db,integrity_key=b"benchmark-only-key")
        latencies=[]; cpu_started=time.process_time(); started=time.perf_counter(); initial_bytes=db.path.stat().st_size
        for index in range(max(1,args.events)):
            event=BackgroundMonitorEvent(event_id=f"benchmark-{index}",timestamp=utc_now_iso(),event_type="benchmark_detection",severity="low",source="benchmark",evidence="identical bounded event",rule_id="BENCH-001")
            before=time.perf_counter(); pipeline.ingest_background_event(event); latencies.append((time.perf_counter()-before)*1000)
        critical=BackgroundMonitorEvent(event_id="benchmark-critical",timestamp=utc_now_iso(),event_type="agent_tampering",severity="critical",source="benchmark-control",evidence="bounded critical insertion",rule_id="BENCH-CRITICAL")
        critical_started=time.perf_counter(); critical_decision=pipeline.ingest_background_event(critical); critical_latency=(time.perf_counter()-critical_started)*1000
        elapsed=time.perf_counter()-started; cpu_elapsed=time.process_time()-cpu_started; ordered=sorted(latencies)
        percentile=lambda p: ordered[min(len(ordered)-1,int(len(ordered)*p))]
        final_bytes=db.path.stat().st_size; pending=len(pipeline.store.pending_notifications(limit=pipeline.config.notification_capacity))
        db.close(); recovery_started=time.perf_counter(); reopened=AuditDatabase(Path(root)/"benchmark.sqlite3"); recovered=ResilientAlertPipeline(reopened,integrity_key=b"benchmark-only-key"); recovery_ms=(time.perf_counter()-recovery_started)*1000
        recovered_count=reopened.conn.execute("SELECT SUM(occurrence_count) AS n FROM resilient_alert_aggregates").fetchone()["n"]
        report={"test_environment":{"platform":__import__("platform").platform(),"python":__import__("platform").python_version(),"duplicate_events":len(latencies),"critical_insertions":1},"configuration":{"notification_capacity":pipeline.config.notification_capacity,"protected_capacity":pipeline.config.protected_capacity,"maximum_active_fingerprints":pipeline.config.maximum_active_fingerprints},"measured":{"duplicate_events_per_second":len(latencies)/elapsed,"elapsed_seconds":elapsed,"process_cpu_seconds":cpu_elapsed,"latency_ms":{"p50":percentile(.50),"p95":percentile(.95),"p99":percentile(.99),"critical_under_duplicate_load":critical_latency},"critical_accepted":critical_decision.accepted,"critical_notify":critical_decision.notify,"maximum_resident_set_platform_units":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,"database_bytes":final_bytes,"database_growth_bytes":final_bytes-initial_bytes,"database_growth_bytes_per_receipt":(final_bytes-initial_bytes)/(len(latencies)+1),"pending_notifications":pending,"restart_recovery_ms":recovery_ms,"recovered_occurrence_count":recovered_count},"not_measured":["multi-process producer saturation","battery/energy impact","central-node workloads","network notification delivery"],"note":"These measurements are a single local run, not product performance guarantees or deployment capacity claims."}
    rendered=json.dumps(report,indent=2,sort_keys=True); print(rendered)
    if args.output: args.output.write_text(rendered+"\n",encoding="utf-8")
    return 0


if __name__=="__main__": raise SystemExit(main())
