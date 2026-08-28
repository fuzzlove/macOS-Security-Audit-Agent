from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable


class Primitive(str, Enum):
    PROCESS_ENUMERATE="process_enumerate"; FOREIGN_PROCESS_OPEN="foreign_process_open"; TASK_PORT_ACQUIRED="task_port_acquired"
    DEBUG_ATTACH="debug_attach"; FOREIGN_MEMORY_READ="foreign_memory_read"; FOREIGN_MEMORY_ALLOCATE="foreign_memory_allocate"
    FOREIGN_MEMORY_WRITE="foreign_memory_write"; FOREIGN_MEMORY_PROTECT="foreign_memory_protect"; SECTION_MAP_CROSS_PROCESS="section_map_cross_process"
    IMAGE_UNMAP="image_unmap"; IMAGE_REMAP="image_remap"; TARGET_THREAD_CREATE="target_thread_create"; TARGET_THREAD_SUSPEND="target_thread_suspend"
    TARGET_THREAD_RESUME="target_thread_resume"; TARGET_THREAD_CONTEXT_CHANGE="target_thread_context_change"; FOREIGN_EXECUTION_QUEUED="foreign_execution_queued"
    EXECUTABLE_PRIVATE_REGION="executable_private_region"; UNBACKED_THREAD_START="unbacked_thread_start"; MODULE_PROVENANCE_MISMATCH="module_provenance_mismatch"
    IMAGE_MEMORY_DISK_MISMATCH="image_memory_disk_mismatch"; FOREIGN_MODULE_LOAD="foreign_module_load"; PROC_MEMORY_WRITE="proc_memory_write"
    PTRACE_ATTACH="ptrace_attach"; IDENTITY_MISMATCH="identity_mismatch"; OUTBOUND_CONNECTION="outbound_connection"; PERSISTENCE_CREATED="persistence_created"
    CHILD_PROCESS_CREATED="child_process_created"


SIGNAL_MAP={
 "task_for_pid":Primitive.TASK_PORT_ACQUIRED,"mach_vm_write":Primitive.FOREIGN_MEMORY_WRITE,"cross_process_memory_write":Primitive.FOREIGN_MEMORY_WRITE,
 "mach_vm_allocate":Primitive.FOREIGN_MEMORY_ALLOCATE,"remote_thread_created":Primitive.TARGET_THREAD_CREATE,"thread_create_running":Primitive.TARGET_THREAD_CREATE,
 "thread_suspend":Primitive.TARGET_THREAD_SUSPEND,"thread_resume":Primitive.TARGET_THREAD_RESUME,"thread_set_state":Primitive.TARGET_THREAD_CONTEXT_CHANGE,
 "thread_state_modified":Primitive.TARGET_THREAD_CONTEXT_CHANGE,"ptrace_attach":Primitive.PTRACE_ATTACH,"proc_memory_write":Primitive.PROC_MEMORY_WRITE,
 "writable_to_executable":Primitive.FOREIGN_MEMORY_PROTECT,"macho_image_in_anonymous_memory":Primitive.EXECUTABLE_PRIVATE_REGION,
 "missing_file_backing":Primitive.UNBACKED_THREAD_START,"foreign_dylib_loaded":Primitive.FOREIGN_MODULE_LOAD,"unsigned_library":Primitive.MODULE_PROVENANCE_MISMATCH,
 "unexpected_dylib_search_resolution":Primitive.MODULE_PROVENANCE_MISMATCH,"image_memory_disk_mismatch":Primitive.IMAGE_MEMORY_DISK_MISMATCH,
 "image_unmap":Primitive.IMAGE_UNMAP,"image_remap":Primitive.IMAGE_REMAP,"foreign_execution_queued":Primitive.FOREIGN_EXECUTION_QUEUED,
 "exception_port_replaced":Primitive.FOREIGN_EXECUTION_QUEUED,"dyld_insert_libraries":Primitive.FOREIGN_MODULE_LOAD,"xpc_dyld_insert_libraries":Primitive.FOREIGN_MODULE_LOAD,
 "unbacked_thread_start":Primitive.UNBACKED_THREAD_START,"foreign_process_open":Primitive.FOREIGN_PROCESS_OPEN,"foreign_memory_read":Primitive.FOREIGN_MEMORY_READ,
}


@dataclass(frozen=True)
class ProcessIdentity:
    host_id:str; boot_id:str; pid:int; start_time:str; executable_hash:str=""; audit_token:str=""; container_id:str=""; workload_id:str=""
    @property
    def stable_id(self)->str:
        material="|".join((self.host_id,self.boot_id,str(self.pid),self.start_time,self.executable_hash,self.audit_token,self.container_id,self.workload_id))
        return "proc-"+hashlib.sha256(material.encode()).hexdigest()[:24]

    @classmethod
    def from_dict(cls,value:dict[str,Any],*,host_id:str="local",boot_id:str="unknown"):
        return cls(host_id,boot_id,int(value.get("pid",0)),str(value.get("start_time") or value.get("started_at") or "unknown"),str(value.get("sha256", "")),str(value.get("audit_token", "")),str(value.get("container_id", "")),str(value.get("workload_id", "")))


@dataclass(frozen=True)
class PrimitiveObservation:
    primitive:str; observed_at:str; source_id:str; target_id:str; sensor:str; sensor_reliability:str; raw_reference:str=""; thread_id:str=""; memory_region_id:str=""; attributes:dict[str,Any]=field(default_factory=dict)


@dataclass
class BehaviorGraph:
    graph_id:str; source_id:str; target_id:str; first_observed_at:str; last_observed_at:str; nodes:list[dict[str,Any]]=field(default_factory=list); edges:list[dict[str,Any]]=field(default_factory=list); evidence_references:list[str]=field(default_factory=list)
    def add(self,event:PrimitiveObservation)->None:
        self.last_observed_at=max(self.last_observed_at,event.observed_at); self.evidence_references=list(dict.fromkeys(self.evidence_references+([event.raw_reference] if event.raw_reference else [])))
        self.edges.append({"edge_id":"edge-"+hashlib.sha256(json.dumps(asdict(event),sort_keys=True,separators=(",", ":")).encode()).hexdigest()[:20],"source":event.source_id,"target":event.target_id,"relationship":event.primitive,"observed_at":event.observed_at,"sensor":event.sensor,"sensor_reliability":event.sensor_reliability,"raw_reference":event.raw_reference,"thread_id":event.thread_id,"memory_region_id":event.memory_region_id,"attributes":event.attributes})
    def primitives(self)->set[str]: return {edge["relationship"] for edge in self.edges}
    def to_dict(self)->dict[str,Any]: return asdict(self)


@dataclass(frozen=True)
class TechniqueTemplate:
    rule_id:str; version:str; name:str; platform:str; required:frozenset[str]; optional:frozenset[str]; contradictions:frozenset[str]; ordered_groups:tuple[tuple[str,...],...]; max_interval_seconds:int; required_sensors:tuple[str,...]; attack_external_id:str; expected_benign_sources:tuple[str,...]; severity:int; author:str="MSAA detection engineering"; reviewer:str="REVIEW_REQUIRED"


TEMPLATES=(
 TechniqueTemplate("PI-MAC-001","2.0","Mach task-port memory injection","macOS",frozenset({Primitive.TASK_PORT_ACQUIRED.value,Primitive.FOREIGN_MEMORY_WRITE.value,Primitive.TARGET_THREAD_CREATE.value}),frozenset({Primitive.FOREIGN_MEMORY_ALLOCATE.value,Primitive.FOREIGN_MEMORY_PROTECT.value}),frozenset(),((Primitive.TASK_PORT_ACQUIRED.value,),(Primitive.FOREIGN_MEMORY_WRITE.value,),(Primitive.TARGET_THREAD_CREATE.value,)),30,("cross_task","memory","thread"),"T1055",("debugger","profiler","endpoint security"),90),
 TechniqueTemplate("PI-MAC-002","2.0","Thread execution hijacking","macOS",frozenset({Primitive.TARGET_THREAD_SUSPEND.value,Primitive.FOREIGN_MEMORY_WRITE.value,Primitive.TARGET_THREAD_CONTEXT_CHANGE.value,Primitive.TARGET_THREAD_RESUME.value}),frozenset({Primitive.TASK_PORT_ACQUIRED.value}),frozenset(),((Primitive.TARGET_THREAD_SUSPEND.value,),(Primitive.FOREIGN_MEMORY_WRITE.value,),(Primitive.TARGET_THREAD_CONTEXT_CHANGE.value,),(Primitive.TARGET_THREAD_RESUME.value,)),30,("cross_task","memory","thread"),"T1055.003",("debugger","crash reporter"),95),
 TechniqueTemplate("PI-MAC-003","2.0","Process image replacement or hollowing-like sequence","macOS",frozenset({Primitive.TARGET_THREAD_SUSPEND.value,Primitive.IMAGE_UNMAP.value,Primitive.IMAGE_REMAP.value,Primitive.TARGET_THREAD_RESUME.value}),frozenset({Primitive.IMAGE_MEMORY_DISK_MISMATCH.value}),frozenset(),((Primitive.TARGET_THREAD_SUSPEND.value,),(Primitive.IMAGE_UNMAP.value,Primitive.IMAGE_REMAP.value),(Primitive.TARGET_THREAD_RESUME.value,)),45,("memory","thread","image"),"T1055.012",("application compatibility component",),100),
 TechniqueTemplate("PI-MAC-004","2.0","ptrace process manipulation","macOS",frozenset({Primitive.PTRACE_ATTACH.value,Primitive.FOREIGN_MEMORY_WRITE.value}),frozenset({Primitive.TARGET_THREAD_CONTEXT_CHANGE.value,Primitive.TARGET_THREAD_RESUME.value}),frozenset(),((Primitive.PTRACE_ATTACH.value,),(Primitive.FOREIGN_MEMORY_WRITE.value,)),30,("trace","memory"),"T1055.008",("debugger","profiler"),75),
 TechniqueTemplate("PI-MAC-005","2.0","Foreign dynamic-library load","macOS",frozenset({Primitive.FOREIGN_MODULE_LOAD.value,Primitive.MODULE_PROVENANCE_MISMATCH.value}),frozenset({Primitive.IDENTITY_MISMATCH.value}),frozenset(),((Primitive.FOREIGN_MODULE_LOAD.value,),(Primitive.MODULE_PROVENANCE_MISMATCH.value,)),30,("loader","signing"),"T1055.001",("accessibility tool","application compatibility component","endpoint security"),70),
 TechniqueTemplate("PI-MAC-006","2.0","Private executable thread start","macOS",frozenset({Primitive.EXECUTABLE_PRIVATE_REGION.value,Primitive.UNBACKED_THREAD_START.value}),frozenset({Primitive.FOREIGN_MEMORY_WRITE.value}),frozenset(),((Primitive.EXECUTABLE_PRIVATE_REGION.value,),(Primitive.UNBACKED_THREAD_START.value,)),30,("memory","thread"),"T1055",("managed runtime","JIT compiler","profiler"),80),
)


@dataclass
class TechniqueComparison:
    technique_id:str; technique_name:str; technique_version:str; relationship_type:str; shared_primitives:list[str]; missing_primitives:list[str]; different_primitives:list[str]; contradictory_evidence:list[str]; similarity_score:int; mapping_confidence:str; data_source:str; retrieval_date:str; attack_validation_status:str="UNVERIFIED"


@dataclass
class InjectionDecision:
    event_classification:str; normalized_primitives:list[str]; graph:dict[str,Any]; comparisons:list[TechniqueComparison]; nearest_known_technique:dict[str,Any]; variant_analysis:dict[str,Any]; novelty_analysis:dict[str,Any]; footprint_similarities:list[dict[str,Any]]; possible_benign_explanations:list[str]; injection_likelihood:int; maliciousness_confidence:int; technique_match_confidence:int; novelty_score:int; severity:str; evidence_completeness:int; sensor_reliability:int; telemetry_gaps:list[str]; confidence_basis:list[str]; research_required:bool=False
    def to_dict(self)->dict[str,Any]: return asdict(self)


def normalize_signals(signals:Iterable[str],*,observed_at:str,source:ProcessIdentity,target:ProcessIdentity,sensor:str,reliability:str,raw_reference:str="")->list[PrimitiveObservation]:
    output=[]
    for signal in sorted({str(s).lower().strip() for s in signals if str(s).strip()}):
        primitive=SIGNAL_MAP.get(signal)
        if primitive: output.append(PrimitiveObservation(primitive.value,observed_at,source.stable_id,target.stable_id,sensor,reliability,raw_reference,attributes={"source_signal":signal}))
    return output


def analyze_graph(graph:BehaviorGraph,*,sensor_gaps:list[str]|None=None,attack_validator:Any=None,attack_metadata:dict[str,str]|None=None,footprints:list[dict[str,Any]]|None=None,benign_contexts:list[dict[str,Any]]|None=None)->InjectionDecision:
    primitives=graph.primitives(); gaps=list(sensor_gaps or []); metadata=attack_metadata or {}; comparisons=[]
    for template in TEMPLATES:
        shared=primitives & (template.required|template.optional); missing=template.required-primitives; different=primitives-(template.required|template.optional); similarity=round(100*len(shared)/max(1,len(template.required|template.optional)))
        if not missing: relation="EXACT_KNOWN_TECHNIQUE_MATCH"
        elif len(template.required & primitives)>=max(1,len(template.required)-1): relation="PARTIAL_KNOWN_TECHNIQUE_MATCH"
        elif similarity>=50: relation="BEHAVIORALLY_SIMILAR_TO_KNOWN_TECHNIQUE"
        else: relation="INSUFFICIENT_EVIDENCE_FOR_TECHNIQUE"
        validation={"validation_status":"UNVERIFIED"} if attack_validator is None else attack_validator.validate(template.attack_external_id)
        comparisons.append(TechniqueComparison(template.attack_external_id,template.name,template.version,relation,sorted(shared),sorted(missing),sorted(different),[],similarity,"high" if not missing else "medium" if similarity>=50 else "low",metadata.get("source","configured local ATT&CK STIX"),metadata.get("retrieval_date","Not verified"),str(validation.get("validation_status","UNVERIFIED"))))
    nearest=max(comparisons,key=lambda c:c.similarity_score); exact=next((c for c in comparisons if c.relationship_type=="EXACT_KNOWN_TECHNIQUE_MATCH"),None)
    invariant_phases=_invariant_phases(primitives); variant=not exact and nearest.relationship_type=="PARTIAL_KNOWN_TECHNIQUE_MATCH" and len(invariant_phases)>=2
    novel=not exact and not variant and (len(invariant_phases)>=2 or bool(primitives & {Primitive.FOREIGN_MEMORY_WRITE.value,Primitive.TARGET_THREAD_CREATE.value,Primitive.TARGET_THREAD_CONTEXT_CHANGE.value,Primitive.UNBACKED_THREAD_START.value}))
    classification="KNOWN_PROCESS_INJECTION_TECHNIQUE_MATCH" if exact else "VARIANT_OF_KNOWN_PROCESS_INJECTION_TECHNIQUE" if variant else "NOVEL_PROCESS_INJECTION_CANDIDATE" if novel else _primitive_classification(primitives)
    completeness=max(0,min(100,round(100*(len(primitives)/(len(primitives)+len(gaps)+2)))))
    sensor_reliability=100 if not gaps else max(10,100-20*len(gaps)); injection=min(100,20*len(invariant_phases)+10*len(primitives & {Primitive.FOREIGN_MEMORY_WRITE.value,Primitive.TARGET_THREAD_CREATE.value,Primitive.UNBACKED_THREAD_START.value})); injection=max(injection,70) if exact else injection; technique_conf=100 if exact else nearest.similarity_score
    benign_matches=_benign_matches(benign_contexts or [],primitives); malicious=max(0,min(100,injection-(25 if benign_matches else 0)+10*len(primitives & {Primitive.PERSISTENCE_CREATED.value,Primitive.OUTBOUND_CONNECTION.value})))
    footprint_matches=_footprint_matches(footprints or [],primitives)
    novelty=0 if exact else min(100,100-nearest.similarity_score+10*len(nearest.different_primitives)); severity="critical" if injection>=80 else "high" if injection>=60 else "medium" if injection>=30 else "low"
    return InjectionDecision(classification,sorted(primitives),graph.to_dict(),comparisons,asdict(nearest),{"relationship":"VARIANT_OF_KNOWN_TECHNIQUE" if variant else "not established","shared":nearest.shared_primitives,"replaced_or_missing":nearest.missing_primitives,"additional":nearest.different_primitives,"changed_ordering":_ordering_changed(graph,nearest.technique_name),"nearest":nearest.technique_name},{"classification":"NOVEL_PROCESS_INJECTION_CANDIDATE" if novel else "not novel","satisfied_invariants":sorted(invariant_phases),"absent_stages":_absent_phases(invariant_phases),"absence_may_reflect_telemetry_gaps":bool(gaps),"nearest_known":nearest.technique_name,"why_not_known":nearest.missing_primitives,"validation_required":["Acquire missing thread, task-port, memory-map, and loader evidence.","Compare recurring observations before proposing a rule."]},footprint_matches,[item["explanation"] for item in benign_matches] or ["Debugger, profiler, endpoint security, accessibility, crash reporting, managed runtime, anti-cheat, or administrative instrumentation may explain the behavior; no benign disposition was selected."],injection,malicious,technique_conf,novelty,severity,completeness,sensor_reliability,gaps,[f"Observed {len(primitives)} normalized primitives across {len(invariant_phases)} invariant phases.",f"Nearest template similarity is {nearest.similarity_score}%." ,"Benign context lowers maliciousness only; it does not erase the event."],research_required=novel)


def _invariant_phases(p:set[str])->set[str]:
    phases=set()
    if p & {Primitive.FOREIGN_PROCESS_OPEN.value,Primitive.TASK_PORT_ACQUIRED.value,Primitive.PTRACE_ATTACH.value,Primitive.DEBUG_ATTACH.value}: phases.add("target_acquisition")
    if p & {Primitive.FOREIGN_MEMORY_WRITE.value,Primitive.FOREIGN_MEMORY_ALLOCATE.value,Primitive.FOREIGN_MEMORY_PROTECT.value,Primitive.IMAGE_UNMAP.value,Primitive.IMAGE_REMAP.value,Primitive.FOREIGN_MODULE_LOAD.value}: phases.add("foreign_modification")
    if p & {Primitive.TARGET_THREAD_CREATE.value,Primitive.TARGET_THREAD_CONTEXT_CHANGE.value,Primitive.FOREIGN_EXECUTION_QUEUED.value,Primitive.UNBACKED_THREAD_START.value}: phases.add("execution_transfer")
    if p & {Primitive.MODULE_PROVENANCE_MISMATCH.value,Primitive.IMAGE_MEMORY_DISK_MISMATCH.value,Primitive.IDENTITY_MISMATCH.value,Primitive.EXECUTABLE_PRIVATE_REGION.value}: phases.add("provenance_mismatch")
    if p & {Primitive.OUTBOUND_CONNECTION.value,Primitive.PERSISTENCE_CREATED.value,Primitive.CHILD_PROCESS_CREATED.value}: phases.add("post_injection_effect")
    return phases


def _absent_phases(p:set[str])->list[str]: return sorted({"target_acquisition","foreign_modification","execution_transfer","provenance_mismatch","post_injection_effect"}-p)
def _primitive_classification(p:set[str])->str:
    if Primitive.FOREIGN_MEMORY_WRITE.value in p:return "CROSS_PROCESS_MEMORY_WRITE_CANDIDATE"
    if Primitive.FOREIGN_MEMORY_READ.value in p:return "CROSS_PROCESS_MEMORY_READ_CANDIDATE"
    if p & {Primitive.TASK_PORT_ACQUIRED.value,Primitive.FOREIGN_PROCESS_OPEN.value,Primitive.PTRACE_ATTACH.value}:return "CROSS_PROCESS_ACCESS_CANDIDATE"
    if p & {Primitive.EXECUTABLE_PRIVATE_REGION.value,Primitive.UNBACKED_THREAD_START.value}:return "EXECUTABLE_MEMORY_ANOMALY"
    return "PROCESS_INJECTION_PRIMITIVE"
def _ordering_changed(graph:BehaviorGraph,_name:str)->bool:return False


def _benign_matches(records:list[dict[str,Any]],p:set[str])->list[dict[str,Any]]:
    now=datetime.now(timezone.utc); results=[]
    for record in records:
        try: active=datetime.fromisoformat(str(record["expires_at"]).replace("Z","+00:00"))>now
        except (KeyError,ValueError): active=False
        expected=set(record.get("expected_primitives",[])); deviations=sorted(p-expected)
        if active and expected and expected.issubset(p): results.append({"catalog_record_id":record.get("catalog_record_id",""),"deviations":deviations,"drift":bool(deviations),"explanation":f"Behavior overlaps reviewed {record.get('tool_name','instrumentation')} profile; deviations={deviations or 'none'}. Human disposition remains required."})
    return results


def _footprint_matches(records:list[dict[str,Any]],p:set[str])->list[dict[str,Any]]:
    results=[]
    for record in records:
        expected=set(record.get("primitives",[])); shared=sorted(p&expected); different=sorted(p^expected); score=round(100*len(shared)/max(1,len(p|expected)))
        if score>=int(record.get("threshold",50)):results.append({"reference_type":record.get("reference_type","procedure"),"reference_id":record.get("reference_id","unverified"),"source":record.get("source","approved local data"),"shared_features":shared,"differing_features":different,"similarity_score":score,"confidence":"medium" if score<80 else "high","attribution_disclaimer":"Behavioral similarity does not establish tool, malware, actor, organization, or government identity."})
    return results
