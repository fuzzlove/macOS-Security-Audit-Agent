from __future__ import annotations

import hashlib
import json
import platform
from collections import deque
from pathlib import Path

from .config import RCEConfig
from .models import EventType, RCEEvent, TelemetryEvent
from .redaction import redact_environment, redact_text, redact_url
from .rules import RuleMatch, evaluate
from .injection import classify_injection
from .injection_analytics import BehaviorGraph, ProcessIdentity, analyze_graph, normalize_signals
from .attack import RCEAttackValidator
from .exploit_primitives import ExploitPrimitiveEngine, crash_signature
from .models import RCEClassification


class RCEAnalyzer:
    """Bounded deterministic rule engine. It never assigns false-positive dispositions."""

    def __init__(self, config: RCEConfig | None = None) -> None:
        self.config = config or RCEConfig()
        self.recent: deque[TelemetryEvent] = deque(maxlen=min(self.config.queue_limit, 10_000))
        self.dropped_events = 0
        self.exploit_engine = ExploitPrimitiveEngine(self.config)

    def sanitize(self, event: TelemetryEvent) -> TelemetryEvent:
        def safe_process(value: dict) -> dict:
            result = dict(value)
            for key in ("command_line", "arguments", "argv"):
                if key in result:
                    result[key] = redact_text(str(result[key]))
            result.pop("environment", None)
            return result

        process = safe_process(event.process)
        parent_process = safe_process(event.parent_process)
        ancestry = tuple(safe_process(item) for item in event.process_ancestry[:32])
        network = dict(event.network_context)
        if "url" in network:
            network["url"] = redact_url(str(network["url"]))
        metadata = dict(event.metadata)
        if isinstance(metadata.get("environment"), dict):
            metadata["environment"] = redact_environment(metadata["environment"], self.config.redacted_environment_keys)
        if "authorization_header" in metadata:
            metadata["authorization_header"] = "[REDACTED]"
        file_context = dict(event.file_context)
        for key in ("content", "contents", "payload"):
            file_context.pop(key, None)
        return TelemetryEvent(**{**event.__dict__, "process": process, "parent_process": parent_process, "process_ancestry": ancestry, "network_context": network, "file_context": file_context, "metadata": metadata})

    def analyze(self, event: TelemetryEvent) -> RCEEvent | None:
        safe = self.sanitize(event)
        matches = evaluate(safe)
        exploit = self.exploit_engine.assess(safe, self.recent)
        if not matches and exploit is None:
            self._remember(safe)
            return None
        score = exploit.score if exploit is not None else min(100, sum(match.weight for match in matches))
        if exploit is None and score < (25 if self.config.sensitivity == "high" else 50):
            self._remember(safe)
            return None
        if exploit is not None:
            event_type = EventType.SUSPECTED.value if exploit.plausible_rce else EventType.CANDIDATE.value
            severity = exploit.severity
            confidence = exploit.confidence
        else:
            event_type = EventType.LIKELY.value if score >= 90 else EventType.POSSIBLE.value if score >= 55 else EventType.CANDIDATE.value
            severity = "critical" if score >= 90 else "high" if score >= 55 else "medium"
            confidence = "high" if score >= 90 else "medium" if score >= 55 else "low"
        raw = json.dumps(safe.__dict__, sort_keys=True, default=list, separators=(",", ":")).encode()
        raw_hash = hashlib.sha256(raw).hexdigest().upper()
        if exploit is not None:
            root = next((item for item in [*exploit.related_events, safe] if item.memory_context.get("memory_safety_crash") or item.kind == "memory_safety_crash"), safe)
            group_material = "|".join(["rce-exploit-sequence", str(root.process.get("sha256") or root.process.get("executable", "")), crash_signature(root)])
        else:
            group_material = "|".join([event_type, str(safe.process.get("executable", "")), str(safe.parent_process.get("executable", "")), ",".join(m.rule_id for m in matches)])
        group_id = hashlib.sha256(group_material.encode()).hexdigest()[:32]
        source_process=safe.metadata.get("source_process", safe.parent_process); target_process=safe.process
        injection = classify_injection(safe.memory_context, source_process=source_process, target_process=target_process)
        injection_payload = injection.to_dict() if injection else {}
        signals=list(safe.memory_context.get("injection_signals",[]))
        if safe.memory_context.get("writable_to_executable"): signals.append("writable_to_executable")
        if safe.memory_context.get("cross_process_execution"): signals.append("remote_thread_created")
        if signals:
            source_identity=ProcessIdentity.from_dict(source_process,host_id=str(safe.metadata.get("host_id","local")),boot_id=str(safe.metadata.get("boot_id","unknown")))
            target_identity=ProcessIdentity.from_dict(target_process,host_id=str(safe.metadata.get("host_id","local")),boot_id=str(safe.metadata.get("boot_id","unknown")))
            observations=normalize_signals(signals,observed_at=safe.observed_at,source=source_identity,target=target_identity,sensor=safe.sensor,reliability=str(safe.metadata.get("sensor_reliability","degraded")),raw_reference=safe.raw_reference)
            graph_id="graph-"+hashlib.sha256((source_identity.stable_id+target_identity.stable_id+safe.observed_at).encode()).hexdigest()[:20]
            graph=BehaviorGraph(graph_id,source_identity.stable_id,target_identity.stable_id,safe.observed_at,safe.observed_at,nodes=[{"id":source_identity.stable_id,"type":"process","identity":source_process},{"id":target_identity.stable_id,"type":"process","identity":target_process}])
            for observation in observations: graph.add(observation)
            validator=RCEAttackValidator(Path(self.config.attack_data_path)) if self.config.attack_data_path else None
            analytics=analyze_graph(graph,sensor_gaps=list(safe.metadata.get("telemetry_gaps",[])),attack_validator=validator,attack_metadata={"source":"configured local ATT&CK STIX","retrieval_date":str(safe.metadata.get("attack_retrieval_date","Not verified"))},footprints=list(safe.metadata.get("footprints",[])),benign_contexts=list(safe.metadata.get("benign_contexts",[])))
            injection_payload["behavioral_analysis"]=analytics.to_dict()
        else:
            analytics=None
        reason_codes = [item.code for item in exploit.reasons] if exploit else []
        reason_descriptions = [item.description for item in exploit.reasons] if exploit else []
        exploit_primitive_names = [item.category for item in exploit.primitives] if exploit else []
        explanation = self._explanation(safe, exploit) if exploit else ""
        attack_mappings = self._attack_mappings(reason_codes, safe)
        result = RCEEvent(
            event_type=event_type, severity=severity, confidence=confidence,
            event_classification=analytics.event_classification if analytics else "",
            rce_classification=exploit.classification if exploit else RCEClassification.INSUFFICIENT.value,
            rce_subtype=exploit.subtype if exploit else "",
            confidence_score=score,
            risk=exploit.risk if exploit else severity,
            why_flagged=explanation,
            reason_evidence=exploit.reasons if exploit else [],
            exploit_primitives=exploit.primitives if exploit else [],
            timeline=exploit.timeline if exploit else [],
            sensor_coverage=exploit.sensor_coverage if exploit else {},
            evidence_completeness_label=exploit.evidence_completeness_label if exploit else "UNKNOWN",
            monotonic_timestamp=float(safe.metadata["monotonic_timestamp"]) if isinstance(safe.metadata.get("monotonic_timestamp"), (int, float)) else None,
            confidence_basis=f"evidence-derived signal score {score}/100: " + "; ".join([*(match.signal for match in matches), *reason_descriptions]),
            observed_behavior=self._observed_behavior(safe), matching_signals=[*(m.signal for m in matches), *reason_codes],
            group_id=group_id, correlation_id=str(safe.metadata.get("correlation_id", "")) or group_id,
            observed_at=safe.observed_at, source_sensor=safe.sensor, sensor_version=safe.sensor_version,
            sensor_health=str(safe.metadata.get("sensor_health", "degraded_polling")), architecture=platform.machine(),
            boot_id=str(safe.metadata.get("boot_id","unknown")),sensor_reliability=analytics.sensor_reliability if analytics else 0,telemetry_gaps=analytics.telemetry_gaps if analytics else list(safe.metadata.get("telemetry_gaps",[])),operating_system_version=platform.mac_ver()[0],kernel_or_build_version=platform.release(),
            rule_ids=[*(m.rule_id for m in matches), *reason_codes], rule_versions=[*(m.version for m in matches), *("1.0" for _ in reason_codes)],
            process=safe.process, parent_process=safe.parent_process, process_ancestry=list(safe.process_ancestry),
            source_process=source_process,target_process=target_process,
            user_context=safe.user_context, service_context=safe.service_context, network_context=safe.network_context,
            file_context=safe.file_context, memory_context=safe.memory_context, package_context=safe.package_context,
            injection_analysis=injection_payload,
            normalized_primitives=[*(analytics.normalized_primitives if analytics else []), *exploit_primitive_names],behavior_graph_reference=str(analytics.graph.get("graph_id","")) if analytics else "",correlation_window=max(self.config.correlation_windows_seconds),injection_likelihood=analytics.injection_likelihood if analytics else 0,maliciousness_confidence=analytics.maliciousness_confidence if analytics else 0,technique_match_confidence=analytics.technique_match_confidence if analytics else 0,novelty_score=analytics.novelty_score if analytics else 0,evidence_completeness=exploit.evidence_completeness if exploit else analytics.evidence_completeness if analytics else 0,possible_benign_explanations=[*(analytics.possible_benign_explanations if analytics else []), *(exploit.benign_factors if exploit else [])],known_technique_comparisons=[item.__dict__ for item in analytics.comparisons] if analytics else [],nearest_known_technique=analytics.nearest_known_technique if analytics else {},variant_analysis=analytics.variant_analysis if analytics else {},novelty_analysis=analytics.novelty_analysis if analytics else {},footprint_similarities=analytics.footprint_similarities if analytics else [],evidence_capture_tier=self.config.evidence_capture_tier,
            application_context=safe.application_context,
            attack_mappings=attack_mappings,
            assumptions=["temporal and parent-child correlation is behavioral evidence, not proof of exploitation", "suspected RCE classification does not establish that arbitrary code execution succeeded"],
            unknowns=self._unknowns(safe), evidence_references=[safe.raw_reference] if safe.raw_reference else [],
            recommended_validation=["Validate process ancestry, signer, executable hash, service ownership, and related network timing.", "Confirm whether activity was authorized and preserve relevant host logs."],
            recommended_containment=["Use approved incident-response procedures after human validation; this monitor does not terminate processes."],
            raw_event_hashes=[raw_hash],
        )
        self._remember(safe)
        return result

    def _remember(self, event: TelemetryEvent) -> None:
        if self.recent.maxlen and len(self.recent) >= self.recent.maxlen:
            self.dropped_events += 1
        self.recent.append(event)

    @staticmethod
    def _explanation(event: TelemetryEvent, assessment) -> str:
        process = event.process.get("name") or event.process.get("executable") or "The affected process"
        reasons = " ".join(item.description for item in assessment.reasons[:6])
        uncertainty = "This event is preserved for analyst validation; the observations are consistent with an exploitation primitive or chain but do not prove that arbitrary code execution succeeded."
        return f"{process} produced security-relevant behavior. {reasons} Confidence is {assessment.confidence.upper()} ({assessment.score}/100). {uncertainty}"

    @staticmethod
    def _attack_mappings(reason_codes: list[str], event: TelemetryEvent) -> list[dict]:
        mappings: list[dict] = []
        if "RCE-R008_POST_CRASH_SHELL" in reason_codes:
            mappings.append({"technique_id": "T1059", "technique": "Command and Scripting Interpreter", "basis": "a related shell or interpreter was observed after the fault", "confidence": "medium"})
        if "RCE-R013_MULTI_STAGE_CORRELATION" in reason_codes and "RCE-R001_MEMORY_FAULT" in reason_codes:
            mappings.append({"technique_id": "T1203", "technique": "Exploitation for Client Execution", "basis": "a memory fault and related execution consequences formed a multi-stage sequence", "confidence": "medium"})
        if event.memory_context.get("cross_process_execution"):
            mappings.append({"technique_id": "T1055", "technique": "Process Injection", "basis": "cross-process execution telemetry was observed", "confidence": "medium"})
        if "RCE-R014_PRIVILEGE_TRANSITION" in reason_codes:
            mappings.append({"technique_id": "T1068", "technique": "Exploitation for Privilege Escalation", "basis": "an unexpected privilege transition followed a related memory-fault sequence", "confidence": "low"})
        if "RCE-R009_UNEXPECTED_NETWORK" in reason_codes and (event.network_context.get("dns_name") or event.network_context.get("protocol")):
            mappings.append({"technique_id": "T1071", "technique": "Application Layer Protocol", "basis": "post-fault network protocol or domain metadata was observed", "confidence": "low"})
        return mappings

    @staticmethod
    def _observed_behavior(event: TelemetryEvent) -> list[str]:
        facts = [f"Telemetry kind: {event.kind}."]
        if event.process:
            facts.append(f"Process: {event.process.get('executable') or event.process.get('name') or 'unknown'} (pid {event.process.get('pid', 'unknown')}).")
        if event.parent_process:
            facts.append(f"Parent: {event.parent_process.get('executable') or event.parent_process.get('name') or 'unknown'} (pid {event.parent_process.get('pid', 'unknown')}).")
        if event.network_context:
            facts.append("Network relationship metadata was observed; packet contents were not collected.")
        if event.file_context:
            facts.append(f"File metadata: {event.file_context.get('path', 'path unavailable')}.")
        return facts

    @staticmethod
    def _unknowns(event: TelemetryEvent) -> list[str]:
        unknowns = []
        if not event.process.get("sha256"):
            unknowns.append("executable hash unavailable")
        if not event.process.get("signing_status"):
            unknowns.append("code-signing status unavailable")
        if not event.process_ancestry:
            unknowns.append("complete process ancestry unavailable")
        if not event.memory_context:
            unknowns.append("memory and injection telemetry unavailable without an entitled sensor")
        return unknowns

    @staticmethod
    def telemetry_loss(*, estimated_lost: int, reason: str, sensor: str, queue_depth: int) -> RCEEvent:
        return RCEEvent(event_type=EventType.TELEMETRY_LOSS.value, severity="high", confidence="high", confidence_basis="bounded queue reported telemetry loss", observed_behavior=[f"Estimated {estimated_lost} events lost or deferred by {sensor}; reason: {reason}; queue depth: {queue_depth}."], matching_signals=["telemetry backpressure or loss"], source_sensor=sensor, sensor_health="failed", unknowns=["content of lost telemetry is unavailable"], recommended_validation=["Inspect sensor and queue health and restore telemetry coverage."])

    @staticmethod
    def health_failure(reason: str, sensor: str = "rce_analyzer") -> RCEEvent:
        return RCEEvent(event_type=EventType.HEALTH_FAILURE.value, severity="high", confidence="high", confidence_basis="monitor self-health failure", observed_behavior=[reason], matching_signals=["monitor health failure"], source_sensor=sensor, sensor_health="failed", recommended_validation=["Restore the failed component and verify a fresh heartbeat."])
