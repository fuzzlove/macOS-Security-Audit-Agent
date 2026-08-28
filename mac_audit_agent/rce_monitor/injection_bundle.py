from __future__ import annotations

import hashlib,json
from datetime import datetime,timedelta,timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from mac_audit_agent.secure_evidence_collection import EvidenceRepository,EvidenceError

from .config import RCEConfig
from .repository import RCERepository


class ProcessInjectionEvidenceCoordinator:
    """Creates a versioned, tamper-evident metadata bundle for a reviewed event."""
    def __init__(self,rce_repository:RCERepository,evidence_repository:EvidenceRepository,config:RCEConfig)->None:
        self.rce=rce_repository; self.evidence=evidence_repository; self.config=config

    def create(self,event_id:str,case_id:str,analyst:str,*,requested_tier:int=1,classification:str="security-sensitive",retention_days:int=30,authorized_tier2:bool=False)->dict[str,Any]:
        event=self.rce.event_detail(event_id)
        if event is None:raise KeyError(event_id)
        tier=max(0,min(int(requested_tier),3))
        if tier>=2 and (not self.config.tier2_memory_capture_enabled or not authorized_tier2):raise PermissionError("Tier 2 targeted memory collection is disabled or not authorized")
        if self.config.evidence_encryption_required:raise EvidenceError("Evidence encryption is required but no approved encryption provider is configured")
        injection=dict(event.get("injection_analysis",{})); behavioral=dict(injection.get("behavioral_analysis",{})); graph=dict(behavioral.get("graph",{})); failures=[]
        sections={
          "event_summary":{"event_id":event_id,"event_type":event.get("event_type"),"observed_behavior":event.get("observed_behavior"),"source_process":injection.get("source_process"),"target_process":injection.get("target_process"),"classification":behavioral.get("event_classification"),"assessment_dimensions":{key:behavioral.get(key) for key in ("injection_likelihood","maliciousness_confidence","technique_match_confidence","novelty_score","severity","evidence_completeness","sensor_reliability")}},
          "normalized_primitives":behavioral.get("normalized_primitives",[]),"behavior_graph":graph,"timeline":sorted(graph.get("edges",[]),key=lambda item:item.get("observed_at","")),"known_technique_comparisons":behavioral.get("comparisons",[]),"variant_analysis":behavioral.get("variant_analysis",{}),"novelty_analysis":behavioral.get("novelty_analysis",{}),"footprint_similarities":behavioral.get("footprint_similarities",[]),"possible_benign_explanations":behavioral.get("possible_benign_explanations",[]),"contradictory_evidence":event.get("contradictory_signals",[]),"missing_evidence":event.get("unknowns",[]),"sensor_coverage":{"health":event.get("sensor_health"),"gaps":behavioral.get("telemetry_gaps",[])},"reviewer_history":event.get("disposition_history",[]),"raw_event_references":event.get("evidence_references",[]),"process_tree":event.get("process_ancestry",[]),"module_map_comparison":event.get("memory_context",{}).get("module_map_comparison",{}),"memory_map_comparison":event.get("memory_context",{}).get("memory_map_comparison",{}),"thread_evidence":event.get("memory_context",{}).get("thread_evidence",[]),"file_evidence":event.get("file_context",{}),"network_evidence":event.get("network_context",{}),"attack_mappings":event.get("attack_mappings",[]),
        }
        artifacts=[]
        for name,payload in sections.items():
            try: artifacts.append(self.evidence.add_json(case_id,f"process_injection_{name}.json",payload,analyst,"PROCESS_INJECTION_TIER_METADATA").to_dict())
            except Exception as exc: failures.append({"section":name,"error_type":type(exc).__name__})
        manifest=self.evidence.generate_manifest(case_id,analyst,schema_version="process-injection-evidence-1.0",event_id=event_id,capture_tier=tier,classification=classification,collection_failures=failures,encryption_status="NOT_ENCRYPTED_PROVIDER_NOT_CONFIGURED")
        manifest_hash=hashlib.sha256(manifest.read_bytes()).hexdigest(); bundle_id=f"pi-bundle-{uuid4()}"; expires=(datetime.now(timezone.utc)+timedelta(days=max(1,retention_days))).isoformat()
        with self.rce.conn:self.rce.conn.execute("INSERT INTO process_injection_evidence_bundles VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(bundle_id,event_id,case_id,datetime.now(timezone.utc).isoformat(),tier,classification,expires,str(manifest),manifest_hash,"NOT_ENCRYPTED_PROVIDER_NOT_CONFIGURED","VERIFIED" if not failures else "PARTIAL",json.dumps(failures,sort_keys=True)))
        self.rce.audit_access(analyst,"EVIDENCE_BUNDLE_CREATE",bundle_id,"SUCCESS" if not failures else "PARTIAL",f"tier={tier}")
        return {"bundle_id":bundle_id,"event_id":event_id,"case_id":case_id,"capture_tier":tier,"manifest_path":str(manifest),"manifest_hash":manifest_hash,"artifacts":artifacts,"collection_failures":failures,"tamper_evident":True,"tamper_proof":False}

    def verify(self,bundle_id:str,actor:str)->dict[str,Any]:
        row=self.rce.conn.execute("SELECT * FROM process_injection_evidence_bundles WHERE bundle_id=?",(bundle_id,)).fetchone()
        if not row:raise KeyError(bundle_id)
        path=Path(row["manifest_path"]); actual=hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""; valid=actual==row["manifest_hash"]
        self.rce.audit_access(actor,"EVIDENCE_BUNDLE_VERIFY",bundle_id,"SUCCESS" if valid else "INTEGRITY_FAILURE")
        return {"bundle_id":bundle_id,"valid":valid,"expected_hash":row["manifest_hash"],"actual_hash":actual,"verification":"tamper-evident manifest hash"}
