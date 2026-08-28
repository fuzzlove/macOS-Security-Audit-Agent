"""Process-centric, signature-independent ransomware behavior correlation.

This is an original MSAA implementation. It consumes normalized metadata from
supported sensors; it does not import, link, translate, or execute third-party
anti-ransomware code.
"""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass, replace
from threading import RLock
from typing import Any

from .models import DetectionDecision, DetectionSignal
from .risk_engine import decide

MODEL_VERSION = "msaa-adaptive-ransomware-1.0"


@dataclass(frozen=True)
class AdaptiveDetectionPolicy:
    short_window_seconds: float = 5.0
    correlation_window_seconds: float = 30.0
    maximum_process_trees: int = 2048
    maximum_events_per_tree: int = 4096
    entropy_file_threshold: int = 5
    rename_threshold: int = 5
    deletion_threshold: int = 5
    directory_spread_threshold: int = 3
    distinct_file_threshold: int = 8
    volume_spread_threshold: int = 2
    minimum_rate_multiplier: float = 4.0
    write_volume_threshold: int = 32 * 1024 * 1024

    def validated(self) -> AdaptiveDetectionPolicy:
        if not 1 <= self.maximum_process_trees <= 100_000:
            raise ValueError("maximum_process_trees must be between 1 and 100000")
        if not 8 <= self.maximum_events_per_tree <= 100_000:
            raise ValueError("maximum_events_per_tree must be between 8 and 100000")
        if not 1 <= self.short_window_seconds <= self.correlation_window_seconds <= 600:
            raise ValueError("correlation windows must be ordered and no longer than 600 seconds")
        if self.minimum_rate_multiplier < 1:
            raise ValueError("minimum_rate_multiplier must be at least 1")
        return self


@dataclass(frozen=True)
class ProcessTrustContext:
    signing_state: str = "UNKNOWN"
    platform_binary: bool = False
    notarized: bool | None = None
    first_seen: bool = False
    executable_location: str = "OTHER"
    interpreter: bool = False
    script_signed: bool | None = None


@dataclass(frozen=True)
class AdaptiveMutationEvent:
    event_id: str
    monotonic_time: float
    process_key: str
    tree_key: str
    path_token: str
    directory_token: str
    volume_token: str
    operation: str
    bytes_changed: int = 0
    entropy_transition: bool = False
    extension_changed: bool = False
    renamed_over_original: bool = False
    original_deleted: bool = False
    canary_modified: bool = False
    ransom_note_pattern: bool = False
    telemetry_complete: bool = True
    expected_events_per_30s: float | None = None
    trust: ProcessTrustContext = ProcessTrustContext()

    def validated(self) -> AdaptiveMutationEvent:
        bounded = {
            "event_id": self.event_id,
            "process_key": self.process_key,
            "tree_key": self.tree_key,
            "path_token": self.path_token,
            "directory_token": self.directory_token,
            "volume_token": self.volume_token,
            "operation": self.operation,
        }
        if any(not value or len(value) > 256 for value in bounded.values()):
            raise ValueError("adaptive event identifiers must be non-empty and at most 256 characters")
        if self.monotonic_time < 0 or self.bytes_changed < 0:
            raise ValueError("adaptive event numeric values must be non-negative")
        if self.expected_events_per_30s is not None and self.expected_events_per_30s < 0:
            raise ValueError("expected event rate must be non-negative")
        return self


@dataclass(frozen=True)
class AdaptiveAssessment:
    model_version: str
    process_tree_key: str
    decision: DetectionDecision
    reason_codes: tuple[str, ...]
    window_evidence: dict[str, Any]
    telemetry_coverage: str
    event_accepted: bool
    automatic_containment_performed: bool = False

    def to_dict(self) -> dict[str, Any]:
        document = asdict(self)
        document["decision"] = self.decision.to_dict()
        return document


class AdaptiveRansomwareDetector:
    """Bounded rolling correlation keyed by a stable process-tree identity."""

    def __init__(self, policy: AdaptiveDetectionPolicy | None = None) -> None:
        self.policy = (policy or AdaptiveDetectionPolicy()).validated()
        self._events: OrderedDict[str, deque[AdaptiveMutationEvent]] = OrderedDict()
        self._seen_event_ids: OrderedDict[str, None] = OrderedDict()
        self._lock = RLock()
        self.evicted_trees = 0
        self.evicted_events = 0
        self.duplicate_events = 0

    def ingest(self, event: AdaptiveMutationEvent) -> AdaptiveAssessment:
        current = event.validated()
        with self._lock:
            if current.event_id in self._seen_event_ids:
                self.duplicate_events += 1
                return self._assessment(current.tree_key, current.monotonic_time, event_accepted=False)
            self._seen_event_ids[current.event_id] = None
            self._seen_event_ids.move_to_end(current.event_id)
            while len(self._seen_event_ids) > self.policy.maximum_process_trees * 4:
                self._seen_event_ids.popitem(last=False)
            queue = self._events.setdefault(current.tree_key, deque())
            self._events.move_to_end(current.tree_key)
            queue.append(current)
            while len(queue) > self.policy.maximum_events_per_tree:
                queue.popleft()
                self.evicted_events += 1
            cutoff = current.monotonic_time - self.policy.correlation_window_seconds
            while queue and queue[0].monotonic_time < cutoff:
                queue.popleft()
            while len(self._events) > self.policy.maximum_process_trees:
                self._events.popitem(last=False)
                self.evicted_trees += 1
            return self._assessment(current.tree_key, current.monotonic_time, event_accepted=True)

    def _assessment(self, tree_key: str, now: float, *, event_accepted: bool) -> AdaptiveAssessment:
        events = tuple(
            item for item in self._events.get(tree_key, ())
            if 0 <= now - item.monotonic_time <= self.policy.correlation_window_seconds
        )
        short = tuple(item for item in events if now - item.monotonic_time <= self.policy.short_window_seconds)
        paths = {item.path_token for item in events}
        directories = {item.directory_token for item in events}
        volumes = {item.volume_token for item in events}
        entropy_paths = {item.path_token for item in events if item.entropy_transition}
        rename_paths = {item.path_token for item in events if item.extension_changed or item.renamed_over_original}
        deletion_paths = {item.path_token for item in events if item.original_deleted or item.operation.lower() == "delete"}
        signals: list[DetectionSignal] = []

        def add(signal_id: str, weight: int, rationale: str, evidence: dict[str, Any]) -> None:
            signals.append(DetectionSignal(signal_id, weight, rationale, evidence))

        if len(entropy_paths) >= self.policy.entropy_file_threshold:
            add("AR_ADAPTIVE_ENTROPY_WAVE", 45, "multiple distinct files transitioned toward encrypted-looking content", {"distinct_files": len(entropy_paths), "window_seconds": self.policy.correlation_window_seconds})
        if len(rename_paths) >= self.policy.rename_threshold:
            add("AR_ADAPTIVE_RENAME_FANOUT", 20, "one process tree renamed or changed extensions across multiple files", {"distinct_files": len(rename_paths)})
        if len(deletion_paths) >= self.policy.deletion_threshold:
            add("AR_ADAPTIVE_DELETION_FANOUT", 25, "one process tree removed originals across multiple files", {"distinct_files": len(deletion_paths)})
        if len(paths) >= self.policy.distinct_file_threshold and len(directories) >= self.policy.directory_spread_threshold:
            add("AR_ADAPTIVE_DIRECTORY_SPREAD", 15, "file mutations spread across several directories", {"distinct_files": len(paths), "directories": len(directories)})
        if len(volumes) >= self.policy.volume_spread_threshold and len(paths) >= self.policy.distinct_file_threshold:
            add("AR_ADAPTIVE_VOLUME_SPREAD", 15, "one process tree modified files across multiple volumes", {"volumes": len(volumes), "distinct_files": len(paths)})
        total_bytes = sum(item.bytes_changed for item in events)
        if total_bytes >= self.policy.write_volume_threshold and len(paths) >= self.policy.entropy_file_threshold:
            add("AR_ADAPTIVE_WRITE_VOLUME", 15, "bounded metadata indicates an unusually large write volume", {"bytes_changed": total_bytes, "distinct_files": len(paths)})
        expected_values = [item.expected_events_per_30s for item in events if item.expected_events_per_30s is not None]
        expected = max(expected_values) if expected_values else None
        if expected is not None and len(events) >= self.policy.distinct_file_threshold:
            multiplier = len(events) / max(1.0, expected)
            if multiplier >= self.policy.minimum_rate_multiplier:
                add("AR_ADAPTIVE_RATE_DEVIATION", 20, "process-tree file activity materially exceeded its local baseline", {"observed": len(events), "expected": expected, "multiplier": round(multiplier, 2)})
        if any(item.canary_modified for item in events):
            add("AR_ADAPTIVE_CANARY", 60, "an approved protected canary changed", {"count": sum(item.canary_modified for item in events)})
        if any(item.ransom_note_pattern for item in events) and (entropy_paths or deletion_paths or rename_paths):
            add("AR_ADAPTIVE_NOTE_SEQUENCE", 30, "a ransom-note pattern followed correlated mutation behavior", {"note_events": sum(item.ransom_note_pattern for item in events)})

        behavior_present = any(signal.weight >= 15 for signal in signals)
        trust = events[-1].trust if events else ProcessTrustContext()
        signing = trust.signing_state.upper()
        if behavior_present and signing in {"UNSIGNED", "AD_HOC", "INVALID", "MODIFIED_AFTER_SIGNING"}:
            add("AR_ADAPTIVE_UNTRUSTED_PROCESS_CONTEXT", 10, "suspicious behavior originated from a process without a valid trusted signature", {"signing_state": signing})
        if behavior_present and trust.first_seen and trust.executable_location.upper() in {"DOWNLOADS", "TEMPORARY", "CACHE"}:
            add("AR_ADAPTIVE_FIRST_SEEN_LOCATION", 15, "a first-seen process executed from a higher-risk transient location", {"location_class": trust.executable_location.upper()})
        if behavior_present and trust.interpreter and trust.script_signed is False:
            add("AR_ADAPTIVE_INTERPRETER_SCRIPT", 10, "an interpreter attributed the behavior to an untrusted script", {})
        coverage_complete = bool(events) and all(item.telemetry_complete for item in events)
        if not coverage_complete:
            add("AR_ADAPTIVE_PARTIAL_COVERAGE", 0, "sensor coverage was incomplete; confidence and automated response are reduced", {})
        decision = decide(signals)
        destructive_families = {
            signal.signal_id for signal in signals
            if signal.signal_id in {
                "AR_ADAPTIVE_ENTROPY_WAVE", "AR_ADAPTIVE_RENAME_FANOUT",
                "AR_ADAPTIVE_DELETION_FANOUT", "AR_ADAPTIVE_CANARY",
                "AR_ADAPTIVE_NOTE_SEQUENCE",
            }
        }
        if decision.automatic_response_eligible and len(destructive_families) < 2:
            decision = replace(decision, automatic_response_eligible=False, recommended_response="manual_review")
        if not coverage_complete and decision.automatic_response_eligible:
            decision = replace(decision, automatic_response_eligible=False, recommended_response="manual_review")
        evidence = {
            "window_seconds": self.policy.correlation_window_seconds,
            "short_window_seconds": self.policy.short_window_seconds,
            "event_count": len(events),
            "short_window_event_count": len(short),
            "distinct_files": len(paths),
            "distinct_directories": len(directories),
            "distinct_volumes": len(volumes),
            "entropy_transition_files": len(entropy_paths),
            "renamed_files": len(rename_paths),
            "deleted_files": len(deletion_paths),
            "bytes_changed": total_bytes,
            "raw_paths_retained": False,
        }
        return AdaptiveAssessment(
            MODEL_VERSION, tree_key, decision,
            tuple(signal.signal_id for signal in signals), evidence,
            "COMPLETE" if coverage_complete else "PARTIAL",
            event_accepted,
        )

    @property
    def retained_event_count(self) -> int:
        with self._lock:
            return sum(len(queue) for queue in self._events.values())


def run_adaptive_detector_demo() -> dict[str, Any]:
    """Run deterministic metadata-only demonstrations of the adaptive engine."""
    unsigned = ProcessTrustContext(
        signing_state="UNSIGNED", first_seen=True, executable_location="TEMPORARY",
    )
    signed = ProcessTrustContext(signing_state="DEVELOPER_ID", notarized=True)

    def event(number: int, *, trust: ProcessTrustContext = unsigned, **changes: Any) -> AdaptiveMutationEvent:
        values: dict[str, Any] = {
            "event_id": f"demo-{number}", "monotonic_time": 100.0 + number,
            "process_key": "demo-process", "tree_key": "demo-tree",
            "path_token": f"path-{number}", "directory_token": f"directory-{number % 3}",
            "volume_token": "volume-1", "operation": "modified",
            "bytes_changed": 8 * 1024 * 1024, "expected_events_per_30s": 1.0,
            "trust": trust,
        }
        values.update(changes)
        return AdaptiveMutationEvent(**values)

    scenarios: list[dict[str, Any]] = []

    def execute(
        scenario_id: str,
        title: str,
        events: list[AdaptiveMutationEvent],
        required: set[str],
        automatic_expected: bool,
    ) -> None:
        detector = AdaptiveRansomwareDetector()
        result = None
        for observation in events:
            result = detector.ingest(observation)
        assert result is not None
        passed = required.issubset(result.reason_codes) and result.decision.automatic_response_eligible is automatic_expected
        scenarios.append({
            "scenario_id": scenario_id, "title": title,
            "result": "PASS" if passed else "FAIL", "passed": passed,
            "score": result.decision.score,
            "automatic_response_eligible": result.decision.automatic_response_eligible,
            "automatic_containment_performed": result.automatic_containment_performed,
            "reason_codes": list(result.reason_codes),
            "window_evidence": result.window_evidence,
            "telemetry_coverage": result.telemetry_coverage,
        })

    execute("AR-ADAPT-01", "Unsigned status alone", [event(1, bytes_changed=1)], set(), False)
    execute(
        "AR-ADAPT-02", "Unsigned multi-file entropy wave",
        [event(number, entropy_transition=True) for number in range(1, 6)],
        {"AR_ADAPTIVE_ENTROPY_WAVE", "AR_ADAPTIVE_UNTRUSTED_PROCESS_CONTEXT"}, False,
    )
    composite = [
        event(number, entropy_transition=True, extension_changed=True, original_deleted=True,
              volume_token=f"volume-{number % 2}", ransom_note_pattern=number == 10)
        for number in range(1, 11)
    ]
    execute(
        "AR-ADAPT-03", "Unsigned correlated ransomware chain", composite,
        {"AR_ADAPTIVE_ENTROPY_WAVE", "AR_ADAPTIVE_RENAME_FANOUT", "AR_ADAPTIVE_DELETION_FANOUT"}, True,
    )
    execute(
        "AR-ADAPT-04", "Signed process with attack behavior",
        [replace(item, event_id=f"signed-{index}", trust=signed) for index, item in enumerate(composite, 1)],
        {"AR_ADAPTIVE_ENTROPY_WAVE", "AR_ADAPTIVE_DELETION_FANOUT"}, True,
    )
    execute(
        "AR-ADAPT-05", "Incomplete sensor coverage",
        [replace(item, event_id=f"partial-{index}", telemetry_complete=False) for index, item in enumerate(composite, 1)],
        {"AR_ADAPTIVE_PARTIAL_COVERAGE"}, False,
    )
    execute(
        "AR-ADAPT-06", "Baseline rate deviation without encryption proof",
        [event(number, bytes_changed=1) for number in range(1, 9)],
        {"AR_ADAPTIVE_RATE_DEVIATION", "AR_ADAPTIVE_DIRECTORY_SPREAD"}, False,
    )
    report: dict[str, Any] = {
        "operation": "adaptive_signature_independent_ransomware_demo",
        "model_version": MODEL_VERSION,
        "scenario_count": len(scenarios),
        "passed_count": sum(item["passed"] for item in scenarios),
        "failed_count": sum(not item["passed"] for item in scenarios),
        "all_passed": all(item["passed"] for item in scenarios),
        "scenarios": scenarios,
        "safety": {
            "filesystem_writes": False, "commands_executed": False,
            "processes_spawned": False, "network_access": False,
            "containment_performed": False,
        },
        "qualification": "This validates original MSAA metadata correlation. It does not prove live Endpoint Security delivery or containment.",
    }
    report["report_sha256"] = hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest()
    return report


__all__ = [
    "MODEL_VERSION", "AdaptiveAssessment", "AdaptiveDetectionPolicy",
    "AdaptiveMutationEvent", "AdaptiveRansomwareDetector", "ProcessTrustContext",
    "run_adaptive_detector_demo",
]
