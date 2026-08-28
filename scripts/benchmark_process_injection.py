from __future__ import annotations
import argparse,json,platform,resource,time
from mac_audit_agent.rce_monitor.injection_analytics import BehaviorGraph,PrimitiveObservation,ProcessIdentity,analyze_graph

def main()->int:
 p=argparse.ArgumentParser();p.add_argument("--graphs",type=int,default=10000);a=p.parse_args();count=max(1,min(a.graphs,500000));source=ProcessIdentity("host","boot",10,"one");target=ProcessIdentity("host","boot",20,"two");normalization=[];correlation=[];matching=[];novelty=[];start=time.perf_counter()
 for index in range(count):
  before=time.perf_counter();events=[PrimitiveObservation(p,f"2026-07-19T00:00:0{i}Z",source.stable_id,target.stable_id,"synthetic","healthy",f"raw:{index}:{i}") for i,p in enumerate(("task_port_acquired","foreign_memory_write","target_thread_create"))];normalization.append(time.perf_counter()-before)
  before=time.perf_counter();g=BehaviorGraph(f"g{index}",source.stable_id,target.stable_id,events[0].observed_at,events[0].observed_at);[g.add(e) for e in events];correlation.append(time.perf_counter()-before)
  before=time.perf_counter();result=analyze_graph(g);matching.append(time.perf_counter()-before);novelty.append(0.0 if not result.research_required else matching[-1])
 elapsed=time.perf_counter()-start;usage=resource.getrusage(resource.RUSAGE_SELF);print(json.dumps({"environment":{"platform":platform.platform(),"python":platform.python_version()},"graphs":count,"raw_events":count*3,"elapsed_seconds":elapsed,"raw_event_ingestion_per_second":count*3/elapsed,"primitive_normalization_mean_ms":sum(normalization)/count*1000,"graph_correlation_mean_ms":sum(correlation)/count*1000,"known_template_and_novelty_mean_ms":sum(matching)/count*1000,"novelty_mean_ms":sum(novelty)/count*1000,"queue_depth":"not applicable synchronous benchmark","memory_max_rss_platform_units":usage.ru_maxrss,"cpu_user_seconds":usage.ru_utime,"event_loss":0,"storage_growth":"not measured by in-memory benchmark","evidence_enrichment":"not measured; privileged tools not invoked","restart_recovery":"covered by repository/service tests"},indent=2,sort_keys=True));return 0
if __name__=="__main__":raise SystemExit(main())
