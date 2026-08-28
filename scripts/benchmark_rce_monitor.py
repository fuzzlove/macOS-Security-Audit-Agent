from __future__ import annotations

import argparse
import json
import resource
import tempfile
import time
from pathlib import Path

from mac_audit_agent.rce_monitor.analyzer import RCEAnalyzer
from mac_audit_agent.rce_monitor.models import TelemetryEvent
from mac_audit_agent.rce_monitor.repository import RCERepository


def main() -> int:
    parser=argparse.ArgumentParser(description="Synthetic, non-exploit RCE analyzer benchmark")
    parser.add_argument("--events",type=int,default=10000); args=parser.parse_args(); count=max(1,min(args.events,1_000_000))
    analyzer=RCEAnalyzer(); latencies=[]; emitted=0
    with tempfile.TemporaryDirectory(prefix="msaa-rce-benchmark-") as root:
        db_path=Path(root)/"events.sqlite3"; repo=RCERepository(db_path); started=time.perf_counter()
        for index in range(count):
            event=TelemetryEvent(kind="process_start",process={"pid":index+10,"executable":"/bin/zsh","command_line":"zsh -c echo fixture"},parent_process={"pid":2,"executable":"/usr/sbin/httpd","is_service":True},service_context={"network_facing":True},raw_reference=f"synthetic:{index}")
            before=time.perf_counter(); result=analyzer.analyze(event); latencies.append(time.perf_counter()-before)
            if result: repo.store_event(result,raw_payload={"fixture":index}); emitted+=1
        elapsed=time.perf_counter()-started; size=db_path.stat().st_size
        status=repo.status(); valid,chain=repo.verify_chain()
        result={"environment":{"python":__import__("platform").python_version(),"platform":__import__("platform").platform()},"events":count,"elapsed_seconds":round(elapsed,6),"ingestion_events_per_second":round(count/elapsed,2),"analysis_latency_mean_ms":round(sum(latencies)/len(latencies)*1000,6),"analysis_latency_max_ms":round(max(latencies)*1000,6),"cve_correlation_latency":"not measured; no approved CVE fixture supplied","queue_depth":len(analyzer.recent),"memory_max_rss_platform_units":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,"cpu_user_seconds":resource.getrusage(resource.RUSAGE_SELF).ru_utime,"storage_bytes":size,"candidate_occurrences":emitted,"grouped_records":status["event_count"],"deduplication_ratio":round(1-(status["event_count"]/max(1,emitted)),6),"dropped_event_count":analyzer.dropped_events,"chain_valid":valid,"chain_detail":chain,"restart_recovery":"covered by automated service restart test"}
        print(json.dumps(result,indent=2,sort_keys=True))
    return 0


if __name__=="__main__": raise SystemExit(main())
