from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class EventType(str, Enum):
    SUSPECTED = "SUSPECTED_REMOTE_CODE_EXECUTION"
    CANDIDATE = "RCE_BEHAVIOR_CANDIDATE"
    POSSIBLE = "POSSIBLE_REMOTE_CODE_EXECUTION"
    LIKELY = "LIKELY_REMOTE_CODE_EXECUTION"
    CONFIRMED = "CONFIRMED_REMOTE_CODE_EXECUTION"
    EXPOSURE = "RCE_VULNERABILITY_EXPOSURE"
    CVE_SIMILAR = "CVE_BEHAVIORAL_SIMILARITY"
    CVE_PROBABLE = "CVE_PROBABLE_MATCH"
    CVE_EXACT = "CVE_EXACT_PRODUCT_VERSION_MATCH"
    SENSOR_DEGRADED = "RCE_SENSOR_DEGRADED"
    TELEMETRY_LOSS = "RCE_TELEMETRY_LOSS"
    POLICY_TAMPER = "RCE_POLICY_TAMPER"
    HEALTH_FAILURE = "RCE_MONITOR_HEALTH_FAILURE"
    INJECTION_SENSOR_DEGRADED = "PROCESS_INJECTION_SENSOR_DEGRADED"
    INJECTION_TELEMETRY_LOSS = "PROCESS_INJECTION_TELEMETRY_LOSS"


class ReviewState(str, Enum):
    OPEN = "OPEN"
    UNREVIEWED = "UNREVIEWED"
    INVESTIGATING = "INVESTIGATING"
    RESEARCH_REQUIRED = "RESEARCH_REQUIRED"


class Disposition(str, Enum):
    CONFIRMED_EXPLOITATION = "CONFIRMED_EXPLOITATION"
    PROBABLE_EXPLOITATION = "PROBABLE_EXPLOITATION"
    SUSPECTED_EXPLOITATION = "SUSPECTED_EXPLOITATION"
    NEEDS_INVESTIGATION = "NEEDS_INVESTIGATION"
    BENIGN_SOFTWARE_BEHAVIOR = "BENIGN_SOFTWARE_BEHAVIOR"
    FUZZING_TEST_ACTIVITY = "FUZZING_TEST_ACTIVITY"
    DEBUGGER_ACTIVITY = "DEBUGGER_ACTIVITY"
    UNABLE_TO_DETERMINE = "UNABLE_TO_DETERMINE"
    CONFIRMED_TRUE_POSITIVE = "CONFIRMED_TRUE_POSITIVE"
    PROBABLE_TRUE_POSITIVE = "PROBABLE_TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN_AUTHORIZED_ACTIVITY = "BENIGN_AUTHORIZED_ACTIVITY"
    MITIGATED = "MITIGATED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    DUPLICATE = "DUPLICATE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    REOPENED = "REOPENED"
    CONFIRMED_MALICIOUS_PROCESS_INJECTION = "CONFIRMED_MALICIOUS_PROCESS_INJECTION"
    PROBABLE_MALICIOUS_PROCESS_INJECTION = "PROBABLE_MALICIOUS_PROCESS_INJECTION"
    CONFIRMED_PROCESS_INJECTION_INTENT_UNKNOWN = "CONFIRMED_PROCESS_INJECTION_INTENT_UNKNOWN"
    BENIGN_AUTHORIZED_INSTRUMENTATION = "BENIGN_AUTHORIZED_INSTRUMENTATION"
    EXPECTED_ADMINISTRATIVE_ACTIVITY = "EXPECTED_ADMINISTRATIVE_ACTIVITY"
    RESEARCH_CANDIDATE = "RESEARCH_CANDIDATE"


@dataclass(frozen=True)
class TelemetryEvent:
    kind: str
    observed_at: str = field(default_factory=utc_now)
    sensor: str = "msaa_system_monitor"
    sensor_version: str = "1"
    process: dict[str, Any] = field(default_factory=dict)
    parent_process: dict[str, Any] = field(default_factory=dict)
    process_ancestry: tuple[dict[str, Any], ...] = ()
    user_context: dict[str, Any] = field(default_factory=dict)
    service_context: dict[str, Any] = field(default_factory=dict)
    network_context: dict[str, Any] = field(default_factory=dict)
    file_context: dict[str, Any] = field(default_factory=dict)
    memory_context: dict[str, Any] = field(default_factory=dict)
    package_context: dict[str, Any] = field(default_factory=dict)
    application_context: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_reference: str = ""


class RCEClassification(str, Enum):
    HIGH_CONFIDENCE = "CONFIRMED_OR_HIGH_CONFIDENCE_RCE"
    PROBABLE = "PROBABLE_RCE"
    SUSPECTED = "SUSPECTED_RCE"
    MEMORY_CORRUPTION = "RCE_LIKE_MEMORY_CORRUPTION"
    CRASH_PRECURSOR = "SUSPICIOUS_CRASH_EXPLOIT_PRECURSOR"
    BENIGN_CRASH = "BENIGN_OR_EXPECTED_CRASH"
    INSUFFICIENT = "INSUFFICIENT_EVIDENCE"


class RCESubtype(str, Enum):
    BUFFER_OVERFLOW = "RCE_BUFFER_OVERFLOW_SUSPECTED"
    STACK_OVERFLOW = "RCE_STACK_OVERFLOW_SUSPECTED"
    HEAP_CORRUPTION = "RCE_HEAP_CORRUPTION_SUSPECTED"
    USE_AFTER_FREE = "RCE_USE_AFTER_FREE_SUSPECTED"
    OUT_OF_BOUNDS = "RCE_OUT_OF_BOUNDS_MEMORY_ACCESS"
    CONTROL_FLOW = "RCE_CONTROL_FLOW_CORRUPTION"
    EXECUTABLE_MEMORY = "RCE_EXECUTABLE_MEMORY_ANOMALY"
    WRITE_THEN_EXECUTE = "RCE_WRITE_THEN_EXECUTE_ANOMALY"
    MEMORY_PROTECTION = "RCE_SUSPICIOUS_MEMORY_PROTECTION_CHANGE"
    CRASH_TO_EXECUTION = "RCE_CRASH_TO_EXECUTION_CHAIN"
    POST_CRASH_PROCESS = "RCE_POST_CRASH_PROCESS_SPAWN"
    POST_CRASH_SHELL = "RCE_POST_CRASH_SHELL_SPAWN"
    CHILD_PROCESS = "RCE_CHILD_PROCESS_ANOMALY"
    EXPLOIT_PRIMITIVE = "RCE_EXPLOIT_PRIMITIVE_SUSPECTED"
    KNOWN_CVE = "RCE_KNOWN_CVE_BEHAVIOR_MATCH"
    UNKNOWN = "RCE_UNKNOWN_EXPLOIT_PATTERN"
    EXPLOIT_CHAIN = "RCE_EXPLOIT_CHAIN_SUSPECTED"


@dataclass(frozen=True)
class RCEReasonEvidence:
    code: str
    description: str
    telemetry_source: str
    observed_at: str
    confidence_contribution: int
    evidence_reference: str = ""


@dataclass(frozen=True)
class ExploitPrimitiveEvidence:
    category: str
    observed_at: str
    telemetry_source: str
    confidence: str
    process_id: int | None = None
    evidence_reference: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RCETimelineEntry:
    timestamp: str
    event_type: str
    summary: str
    source: str
    evidence_reference: str = ""


@dataclass
class CVECorrelation:
    cve_id: str
    relationship_type: str
    confidence: str
    confidence_basis: str
    source: str
    source_record_hash: str
    source_retrieval_date: str
    affected_product: str = ""
    affected_component: str = ""
    affected_version_range: str = ""
    observed_product: str = ""
    observed_version: str = ""
    version_match_status: str = "unknown"
    backport_status: str = "unknown"
    matching_criteria: list[str] = field(default_factory=list)
    non_matching_criteria: list[str] = field(default_factory=list)
    unknown_criteria: list[str] = field(default_factory=list)
    observed_behavior_summary: str = ""
    cve_behavior_summary: str = ""
    mitigation_summary: str = ""
    validation_required: list[str] = field(default_factory=list)
    conclusion: str = ""
    similarity_percent: int = 0


@dataclass
class RCEEvent:
    event_type: str
    severity: str
    confidence: str
    confidence_basis: str
    observed_behavior: list[str]
    matching_signals: list[str]
    event_classification: str = ""
    rce_classification: str = RCEClassification.INSUFFICIENT.value
    rce_subtype: str = ""
    confidence_score: int = 0
    risk: str = "informational"
    why_flagged: str = ""
    reason_evidence: list[RCEReasonEvidence] = field(default_factory=list)
    exploit_primitives: list[ExploitPrimitiveEvidence] = field(default_factory=list)
    timeline: list[RCETimelineEntry] = field(default_factory=list)
    sensor_coverage: dict[str, str] = field(default_factory=dict)
    evidence_completeness_label: str = "UNKNOWN"
    monotonic_timestamp: float | None = None
    original_classification: str = ""
    original_confidence_score: int = 0
    behavior_model_version: str = "rce-explainable-1"
    event_id: str = field(default_factory=lambda: f"rce-{uuid4()}")
    schema_version: str = "1.0"
    correlation_id: str = ""
    group_id: str = ""
    host_id: str = "local"
    boot_id: str = "unknown"
    case_id: str = ""
    research_candidate_id: str = ""
    workload_id: str = ""
    container_id: str = ""
    tenant_id: str = ""
    observed_at: str = field(default_factory=utc_now)
    first_observed_at: str = ""
    last_observed_at: str = ""
    ingestion_at: str = field(default_factory=utc_now)
    source_sensor: str = "msaa_system_monitor"
    sensor_version: str = "1"
    sensor_health: str = "degraded_polling"
    sensor_reliability: int = 0
    telemetry_gaps: list[str] = field(default_factory=list)
    dropped_event_estimate: int = 0
    operating_system: str = "macOS"
    operating_system_version: str = ""
    kernel_or_build_version: str = ""
    architecture: str = ""
    environment: str = "host"
    review_state: str = ReviewState.OPEN.value
    disposition: str = ""
    disposition_reason: str = ""
    rule_ids: list[str] = field(default_factory=list)
    rule_versions: list[str] = field(default_factory=list)
    process: dict[str, Any] = field(default_factory=dict)
    parent_process: dict[str, Any] = field(default_factory=dict)
    source_process: dict[str, Any] = field(default_factory=dict)
    target_process: dict[str, Any] = field(default_factory=dict)
    source_thread: dict[str, Any] = field(default_factory=dict)
    target_threads: list[dict[str, Any]] = field(default_factory=list)
    process_ancestry: list[dict[str, Any]] = field(default_factory=list)
    user_context: dict[str, Any] = field(default_factory=dict)
    session_context: dict[str, Any] = field(default_factory=dict)
    token_or_privilege_context: dict[str, Any] = field(default_factory=dict)
    cross_process_access: dict[str, Any] = field(default_factory=dict)
    service_context: dict[str, Any] = field(default_factory=dict)
    network_context: dict[str, Any] = field(default_factory=dict)
    file_context: dict[str, Any] = field(default_factory=dict)
    memory_context: dict[str, Any] = field(default_factory=dict)
    memory_regions: list[dict[str, Any]] = field(default_factory=list)
    memory_operations: list[dict[str, Any]] = field(default_factory=list)
    thread_operations: list[dict[str, Any]] = field(default_factory=list)
    module_context: dict[str, Any] = field(default_factory=dict)
    image_context: dict[str, Any] = field(default_factory=dict)
    ipc_context: dict[str, Any] = field(default_factory=dict)
    normalized_primitives: list[str] = field(default_factory=list)
    behavior_graph_reference: str = ""
    correlation_window: int = 0
    injection_likelihood: int = 0
    maliciousness_confidence: int = 0
    technique_match_confidence: int = 0
    novelty_score: int = 0
    evidence_completeness: int = 0
    injection_analysis: dict[str, Any] = field(default_factory=dict)
    possible_benign_explanations: list[str] = field(default_factory=list)
    known_technique_comparisons: list[dict[str, Any]] = field(default_factory=list)
    nearest_known_technique: dict[str, Any] = field(default_factory=dict)
    variant_analysis: dict[str, Any] = field(default_factory=dict)
    novelty_analysis: dict[str, Any] = field(default_factory=dict)
    footprint_similarities: list[dict[str, Any]] = field(default_factory=list)
    evidence_bundle_id: str = ""
    evidence_capture_tier: int = 0
    evidence_collection_failures: list[dict[str, Any]] = field(default_factory=list)
    suppression_status: str = "not_suppressed"
    benign_context_matches: list[dict[str, Any]] = field(default_factory=list)
    package_context: dict[str, Any] = field(default_factory=dict)
    application_context: dict[str, Any] = field(default_factory=dict)
    contradictory_signals: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    evidence_references: list[str] = field(default_factory=list)
    cve_correlations: list[CVECorrelation] = field(default_factory=list)
    attack_mappings: list[dict[str, Any]] = field(default_factory=list)
    recommended_validation: list[str] = field(default_factory=list)
    recommended_containment: list[str] = field(default_factory=list)
    raw_event_hashes: list[str] = field(default_factory=list)
    redaction_status: str = "redacted"
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        self.first_observed_at = self.first_observed_at or self.observed_at
        self.last_observed_at = self.last_observed_at or self.observed_at
        self.correlation_id = self.correlation_id or self.event_id
        self.group_id = self.group_id or self.correlation_id
        self.confidence_score = max(0, min(100, int(self.confidence_score)))
        self.original_classification = self.original_classification or self.rce_classification
        self.original_confidence_score = self.original_confidence_score or self.confidence_score
        if self.disposition == Disposition.FALSE_POSITIVE.value:
            raise ValueError("detectors may not initialize an event as FALSE_POSITIVE")
        if self.event_type == EventType.CONFIRMED.value and self.review_state != ReviewState.INVESTIGATING.value:
            raise ValueError("confirmed RCE requires explicit reviewed evidence")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
