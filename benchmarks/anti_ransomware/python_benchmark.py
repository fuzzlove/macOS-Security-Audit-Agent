from __future__ import annotations

import json, os, resource, statistics, tempfile, threading, time
from pathlib import Path
from mac_audit_agent.anti_ransomware.file_statistics import analyze_bytes
from mac_audit_agent.anti_ransomware.service import BoundedAnalysisService
from mac_audit_agent.anti_ransomware.evidence import EvidenceRecord, RansomwareEvidenceStore


def measure(iterations: int = 500) -> dict:
    sample = os.urandom(65536); latencies=[]
    start=time.perf_counter()
    for _ in range(iterations):
        then=time.perf_counter_ns(); analyze_bytes(sample); latencies.append((time.perf_counter_ns()-then)/1e6)
    handled=[]; service=BoundedAnalysisService(handled.append,max_queue=128); service.start()
    for i in range(500): service.submit(i,priority=1,sequence=i)
    service.stop(5)
    with tempfile.TemporaryDirectory(prefix="msaa-ar-benchmark-") as root:
        store=RansomwareEvidenceStore(Path(root)/"bench.sqlite3"); db_start=time.perf_counter_ns()
        for i in range(100): store.append(EvidenceRecord(f"e{i}","i",f"2026-01-01T00:00:{i%60:02d}Z","benchmark",{"sequence":i,"path_token":"redacted"}))
        db_ms=(time.perf_counter_ns()-db_start)/1e6; db_size=store.path.stat().st_size; store.close()
    usage=resource.getrusage(resource.RUSAGE_SELF)
    return {"iterations":iterations,"feature_latency_ms":{"median":statistics.median(latencies),"p95":sorted(latencies)[int(len(latencies)*.95)-1],"maximum":max(latencies)},"throughput_per_second":iterations/(time.perf_counter()-start),"queue":{"accepted":service.accepted,"dropped":service.dropped,"processed":service.processed,"final_depth":service.queue_depth},"database":{"records":100,"write_ms":db_ms,"bytes":db_size},"process":{"max_rss_raw":usage.ru_maxrss,"threads":len(threading.enumerate())},"native_metrics":"NOT_VERIFIED"}


if __name__ == "__main__": print(json.dumps(measure(),indent=2,sort_keys=True))
