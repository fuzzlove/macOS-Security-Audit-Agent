from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable


@dataclass(frozen=True)
class InjectionTechnique:
    technique_id: str
    name: str
    family: str
    sophistication: str
    required_signals: frozenset[str]
    supporting_signals: frozenset[str] = frozenset()
    description: str = ""


KNOWN_TECHNIQUES = (
    InjectionTechnique("MSAA-PI-001", "Dynamic loader environment injection", "DYLD_INSERT_LIBRARIES", "basic", frozenset({"dyld_insert_libraries"}), frozenset({"foreign_dylib_loaded", "unsigned_library"}), "A target starts with a library inserted through a dyld environment variable."),
    InjectionTechnique("MSAA-PI-002", "Dynamic library hijacking", "dylib_hijacking", "basic", frozenset({"unexpected_dylib_search_resolution"}), frozenset({"foreign_dylib_loaded", "unsigned_library", "writable_library_path"}), "A loader search path resolves a dependency to an unexpected library."),
    InjectionTechnique("MSAA-PI-003", "Mach task-port memory injection", "mach_task_port_injection", "advanced", frozenset({"task_for_pid", "mach_vm_write", "remote_thread_created"}), frozenset({"mach_vm_allocate", "writable_to_executable", "thread_create_running"}), "An injector obtains a task port, writes target memory, and creates or redirects execution."),
    InjectionTechnique("MSAA-PI-004", "Mach thread-state hijacking", "mach_thread_hijacking", "advanced", frozenset({"task_for_pid", "thread_set_state"}), frozenset({"thread_suspend", "mach_vm_write", "thread_resume"}), "An existing target thread is suspended or modified so its instruction state enters injected code."),
    InjectionTechnique("MSAA-PI-005", "ptrace-based process manipulation", "ptrace_injection", "advanced", frozenset({"ptrace_attach", "cross_process_memory_write"}), frozenset({"thread_state_modified", "debug_exception_port"}), "A tracing relationship is used to alter another process memory or execution state."),
    InjectionTechnique("MSAA-PI-006", "Mach exception-port execution redirection", "mach_exception_port_hijacking", "advanced", frozenset({"exception_port_replaced", "thread_state_modified"}), frozenset({"task_for_pid", "cross_process_memory_write"}), "A task or thread exception-port path is changed and used to redirect execution."),
    InjectionTechnique("MSAA-PI-007", "Reflective or memory-only Mach-O loading", "reflective_macho_loading", "advanced", frozenset({"macho_image_in_anonymous_memory", "writable_to_executable"}), frozenset({"missing_file_backing", "manual_symbol_resolution"}), "A Mach-O-like image is mapped or reconstructed in memory without a normal file-backed loader path."),
    InjectionTechnique("MSAA-PI-008", "XPC dyld environment propagation", "xpc_dyld_injection", "advanced", frozenset({"xpc_dyld_insert_libraries"}), frozenset({"foreign_dylib_loaded", "unsigned_library"}), "An XPC service receives a dyld insertion environment and loads a foreign library."),
)


@dataclass
class InjectionAssessment:
    assessment_id: str
    classification: str
    technique_id: str
    technique_name: str
    technique_family: str
    sophistication: str
    confidence: str
    confidence_basis: str
    verified_signals: list[str]
    supporting_signals: list[str]
    contradictory_signals: list[str]
    unknowns: list[str]
    source_process: dict[str, Any] = field(default_factory=dict)
    target_process: dict[str, Any] = field(default_factory=dict)
    requires_human_validation: bool = True
    novel_investigation_id: str = ""
    evidence_plan: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]: return asdict(self)


def _novel_id(signals: Iterable[str], source: dict[str,Any], target: dict[str,Any]) -> str:
    material={"signals":sorted(set(signals)),"source_path":source.get("executable", ""),"target_path":target.get("executable", ""),"platform":"macOS"}
    return "MSAA-PI-UNKNOWN-"+hashlib.sha256(json.dumps(material,sort_keys=True,separators=(",", ":")).encode()).hexdigest()[:12].upper()


def classify_injection(memory_context: dict[str,Any], *, source_process: dict[str,Any]|None=None, target_process: dict[str,Any]|None=None) -> InjectionAssessment | None:
    source=dict(source_process or {}); target=dict(target_process or {})
    signals={str(value).strip().lower() for value in memory_context.get("injection_signals",[]) if str(value).strip()}
    if memory_context.get("writable_to_executable"): signals.add("writable_to_executable")
    if memory_context.get("cross_process_execution"): signals.add("remote_thread_created")
    contradictory=[str(v) for v in memory_context.get("contradictory_signals",[]) if str(v)]
    if not signals: return None
    matches=[]
    for technique in KNOWN_TECHNIQUES:
        if technique.required_signals.issubset(signals):
            support=signals & technique.supporting_signals
            matches.append((len(technique.required_signals)*10+len(support),technique,support))
    if matches:
        _, technique, support=max(matches,key=lambda item:item[0])
        confidence="high" if not contradictory and len(technique.required_signals)>=2 else "medium"
        return InjectionAssessment(assessment_id="inj-"+hashlib.sha256((technique.technique_id+"|"+"|".join(sorted(signals))).encode()).hexdigest()[:16],classification="KNOWN_PROCESS_INJECTION_TECHNIQUE",technique_id=technique.technique_id,technique_name=technique.name,technique_family=technique.family,sophistication=technique.sophistication,confidence=confidence,confidence_basis=f"All required deterministic signals for {technique.technique_id} were supplied by the sensor; this remains an analyst-review finding.",verified_signals=sorted(technique.required_signals),supporting_signals=sorted(support),contradictory_signals=contradictory,unknowns=_unknowns(memory_context,source,target),source_process=source,target_process=target,evidence_plan=build_evidence_plan(source,target,technique.technique_id))
    # Avoid naming a new technique from generic RWX alone. A novel candidate
    # requires at least two cross-process/loader/thread primitives.
    meaningful={s for s in signals if s not in {"writable_to_executable","unsigned_library","missing_file_backing"}}
    if len(meaningful)<2: return InjectionAssessment(assessment_id="inj-observation-"+hashlib.sha256("|".join(sorted(signals)).encode()).hexdigest()[:16],classification="INSUFFICIENT_EVIDENCE_FOR_PROCESS_INJECTION",technique_id="UNCLASSIFIED",technique_name="Unclassified injection indicator",technique_family="unknown",sophistication="unknown",confidence="low",confidence_basis="The observed memory or loader signal is not sufficient to establish cross-process injection.",verified_signals=sorted(signals),supporting_signals=[],contradictory_signals=contradictory,unknowns=_unknowns(memory_context,source,target),source_process=source,target_process=target,evidence_plan=build_evidence_plan(source,target,"UNCLASSIFIED"))
    novel=_novel_id(signals,source,target)
    return InjectionAssessment(assessment_id="inj-"+novel.lower(),classification="POSSIBLE_NOVEL_PROCESS_INJECTION",technique_id=novel,technique_name="Unmatched macOS process-injection signal combination",technique_family="unclassified",sophistication="unknown",confidence="low",confidence_basis="Multiple process-manipulation signals were observed but do not satisfy a named, versioned MSAA technique definition.",verified_signals=sorted(signals),supporting_signals=[],contradictory_signals=contradictory,unknowns=_unknowns(memory_context,source,target),source_process=source,target_process=target,novel_investigation_id=novel,evidence_plan=build_evidence_plan(source,target,novel))


def _unknowns(context:dict[str,Any],source:dict[str,Any],target:dict[str,Any])->list[str]:
    values=[]
    if not source.get("sha256"): values.append("source executable hash unavailable")
    if not target.get("sha256"): values.append("target executable hash unavailable")
    if not context.get("memory_map_reference"): values.append("target memory-map snapshot unavailable")
    if not context.get("thread_state_reference"): values.append("thread-state evidence unavailable")
    return values


def build_evidence_plan(source:dict[str,Any],target:dict[str,Any],technique_id:str)->dict[str,Any]:
    source_pid=source.get("pid"); target_pid=target.get("pid")
    tools=[
      {"tool":"ps","path":"/bin/ps","purpose":"process identity, parent, user, start time, and redacted arguments","arguments":["-p",str(target_pid or "<target-pid>"),"-o","pid=,ppid=,user=,lstart=,comm=,args="],"privilege":"current user where permitted"},
      {"tool":"codesign","path":"/usr/bin/codesign","purpose":"signature, Team ID, signing identifier, and entitlements","arguments":["-dvvv","--entitlements",":-",str(target.get("executable") or "<target-path>")],"privilege":"read access"},
      {"tool":"vmmap","path":"/usr/bin/vmmap","purpose":"memory regions, protections, and file backing","arguments":["-interleaved",str(target_pid or "<target-pid>")],"privilege":"may require administrator or development entitlement"},
      {"tool":"lsof","path":"/usr/sbin/lsof","purpose":"open files, loaded libraries, sockets, and endpoints","arguments":["-nP","-p",str(target_pid or "<target-pid>")],"privilege":"may require administrator"},
      {"tool":"sample","path":"/usr/bin/sample","purpose":"bounded thread stacks for analyst review","arguments":[str(target_pid or "<target-pid>"),"1","1"],"privilege":"may require administrator"},
      {"tool":"log","path":"/usr/bin/log","purpose":"bounded Unified Log window for process, crash, Endpoint Security, and loader context","arguments":["show","--last","5m","--style","json"],"privilege":"log access; apply a reviewed predicate"},
    ]
    return {"schema_version":"1.0","technique_id":technique_id,"source_pid":source_pid,"target_pid":target_pid,"required_artifacts":["process metadata and ancestry","source and target SHA-256 hashes","source and target code-signing metadata","target vmmap snapshot","loaded libraries and open files","thread stacks","network socket metadata","bounded Unified Log window","relevant executable/library copies where policy permits","chain-of-custody manifest"],"tools":tools,"pcap":{"automatic":False,"status":"REQUIRES_EXPLICIT_ANALYST_APPROVAL","tool":"/usr/sbin/tcpdump","recommended_snap_length":96,"purpose":"capture bounded network headers/timing relevant to the source or target endpoints","warnings":["Packet capture can contain sensitive or regulated information.","A PID cannot be used directly as a BPF filter; validate endpoints first.","Use the narrowest interface, host, port, duration, and retention possible."],"required_parameters":["approved interface","reviewed BPF host/port filter","bounded duration","protected output path"]},"validation":["Confirm source-to-target relationship and exact timestamps.","Distinguish debugger, accessibility, security tooling, crash reporting, and developer activity.","Validate every named API signal against sensor provenance.","Do not terminate either process before preservation unless containment urgency requires it."]}
