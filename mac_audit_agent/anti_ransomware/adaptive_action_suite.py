"""Twenty safe, deterministic action tests for adaptive ransomware detection."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from typing import Any, Callable

from .adaptive_detector import (
    MODEL_VERSION,
    AdaptiveMutationEvent,
    AdaptiveRansomwareDetector,
    ProcessTrustContext,
)

SUITE_VERSION = "msaa-adaptive-ransomware-actions-1.0"

UNSIGNED = ProcessTrustContext(
    signing_state="UNSIGNED", first_seen=True, executable_location="TEMPORARY",
)
SIGNED = ProcessTrustContext(signing_state="DEVELOPER_ID", notarized=False)
NOTARIZED = ProcessTrustContext(signing_state="DEVELOPER_ID", notarized=True)
INTERPRETER = ProcessTrustContext(
    signing_state="APPLE", interpreter=True, script_signed=False,
    first_seen=True, executable_location="DOWNLOADS",
)


def _events(
    count: int,
    *,
    trust: ProcessTrustContext = UNSIGNED,
    spacing: float = 1.0,
    expected_rate: float | None = 1.0,
    bytes_changed: int = 8 * 1024 * 1024,
    entropy: bool = False,
    rename: bool = False,
    delete: bool = False,
    canary_at_end: bool = False,
    note_at_end: bool = False,
    volumes: int = 1,
    directories: int = 3,
    telemetry_complete: bool = True,
) -> list[AdaptiveMutationEvent]:
    return [
        AdaptiveMutationEvent(
            event_id=f"action-{number}",
            monotonic_time=100.0 + number * spacing,
            process_key="action-process",
            tree_key="action-tree",
            path_token=f"path-{number}",
            directory_token=f"directory-{number % max(1, directories)}",
            volume_token=f"volume-{number % max(1, volumes)}",
            operation="delete" if delete else "modified",
            bytes_changed=bytes_changed,
            entropy_transition=entropy,
            extension_changed=rename,
            renamed_over_original=rename,
            original_deleted=delete,
            canary_modified=canary_at_end and number == count,
            ransom_note_pattern=note_at_end and number == count,
            telemetry_complete=telemetry_complete,
            expected_events_per_30s=expected_rate,
            trust=trust,
        )
        for number in range(1, count + 1)
    ]


@dataclass(frozen=True)
class AdaptiveActionCase:
    case_id: str
    title: str
    action: str
    build_events: Callable[[], list[AdaptiveMutationEvent]]
    required_reason_codes: tuple[str, ...]
    automatic_response_expected: bool
    expected_coverage: str = "COMPLETE"

    def metadata(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("build_events")
        return value


ACTION_CASES: tuple[AdaptiveActionCase, ...] = (
    AdaptiveActionCase("AR-ACT-01", "Distinct-file entropy wave", "Five separate files transition toward encrypted-looking content.", lambda: _events(5, entropy=True), ("AR_ADAPTIVE_ENTROPY_WAVE",), False),
    AdaptiveActionCase("AR-ACT-02", "Extension and rename fanout", "One process tree renames five distinct files.", lambda: _events(5, rename=True), ("AR_ADAPTIVE_RENAME_FANOUT",), False),
    AdaptiveActionCase("AR-ACT-03", "Original deletion fanout", "One process tree removes five distinct originals.", lambda: _events(5, delete=True), ("AR_ADAPTIVE_DELETION_FANOUT",), False),
    AdaptiveActionCase("AR-ACT-04", "Directory traversal burst", "Eight mutations spread across three directories above baseline.", lambda: _events(8, bytes_changed=1), ("AR_ADAPTIVE_DIRECTORY_SPREAD", "AR_ADAPTIVE_RATE_DEVIATION"), False),
    AdaptiveActionCase("AR-ACT-05", "Cross-volume mutation spread", "Eight mutations span two volumes and three directories.", lambda: _events(8, bytes_changed=1, volumes=2), ("AR_ADAPTIVE_VOLUME_SPREAD",), False),
    AdaptiveActionCase("AR-ACT-06", "High write-volume burst", "Five distinct files account for at least 32 MiB of writes.", lambda: _events(5), ("AR_ADAPTIVE_WRITE_VOLUME",), False),
    AdaptiveActionCase("AR-ACT-07", "Protected canary modification", "A protected canary changes without a second destructive family.", lambda: _events(1, bytes_changed=1, canary_at_end=True), ("AR_ADAPTIVE_CANARY",), False),
    AdaptiveActionCase("AR-ACT-08", "Entropy and rename chain", "An encryption-like wave also renames each affected file.", lambda: _events(5, entropy=True, rename=True), ("AR_ADAPTIVE_ENTROPY_WAVE", "AR_ADAPTIVE_RENAME_FANOUT"), True),
    AdaptiveActionCase("AR-ACT-09", "Entropy and deletion chain", "An encryption-like wave removes the original files.", lambda: _events(5, entropy=True, delete=True), ("AR_ADAPTIVE_ENTROPY_WAVE", "AR_ADAPTIVE_DELETION_FANOUT"), True),
    AdaptiveActionCase("AR-ACT-10", "Entropy followed by ransom note", "A note pattern follows a distinct-file entropy wave.", lambda: _events(5, entropy=True, note_at_end=True), ("AR_ADAPTIVE_ENTROPY_WAVE", "AR_ADAPTIVE_NOTE_SEQUENCE"), True),
    AdaptiveActionCase("AR-ACT-11", "Rename and deletion replacement", "Original files are deleted while replacements receive changed names.", lambda: _events(5, rename=True, delete=True), ("AR_ADAPTIVE_RENAME_FANOUT", "AR_ADAPTIVE_DELETION_FANOUT"), True),
    AdaptiveActionCase("AR-ACT-12", "Full unsigned mutation chain", "Unsigned first-seen software encrypts, renames, deletes, and writes a note.", lambda: _events(10, entropy=True, rename=True, delete=True, note_at_end=True, volumes=2), ("AR_ADAPTIVE_UNTRUSTED_PROCESS_CONTEXT", "AR_ADAPTIVE_NOTE_SEQUENCE"), True),
    AdaptiveActionCase("AR-ACT-13", "Signed software attack behavior", "A valid Developer ID does not exempt destructive behavior.", lambda: _events(10, trust=SIGNED, entropy=True, rename=True, delete=True), ("AR_ADAPTIVE_ENTROPY_WAVE", "AR_ADAPTIVE_DELETION_FANOUT"), True),
    AdaptiveActionCase("AR-ACT-14", "Notarized software attack behavior", "Notarization does not suppress a correlated destructive sequence.", lambda: _events(10, trust=NOTARIZED, entropy=True, rename=True, delete=True), ("AR_ADAPTIVE_ENTROPY_WAVE", "AR_ADAPTIVE_RENAME_FANOUT"), True),
    AdaptiveActionCase("AR-ACT-15", "Interpreter-attributed script chain", "An Apple interpreter is attributed to an untrusted script performing destructive behavior.", lambda: _events(10, trust=INTERPRETER, entropy=True, rename=True, delete=True), ("AR_ADAPTIVE_INTERPRETER_SCRIPT",), True),
    AdaptiveActionCase("AR-ACT-16", "First-seen temporary executable", "A first-seen temporary executable adds context to a multi-file destructive chain.", lambda: _events(8, entropy=True, rename=True), ("AR_ADAPTIVE_FIRST_SEEN_LOCATION",), True),
    AdaptiveActionCase("AR-ACT-17", "Partial telemetry fail-safe", "The chain scores highly but incomplete sensor coverage disables automatic response.", lambda: _events(10, entropy=True, rename=True, delete=True, telemetry_complete=False), ("AR_ADAPTIVE_PARTIAL_COVERAGE",), False, "PARTIAL"),
    AdaptiveActionCase("AR-ACT-18", "Behavior without a learned baseline", "Strong destructive correlation remains visible during baseline cold start.", lambda: _events(8, expected_rate=None, entropy=True, delete=True), ("AR_ADAPTIVE_ENTROPY_WAVE", "AR_ADAPTIVE_DELETION_FANOUT"), True),
    AdaptiveActionCase("AR-ACT-19", "Low-and-slow thirty-second chain", "Five qualifying mutations spread across 28 seconds remain correlated.", lambda: _events(5, spacing=7.0, entropy=True, rename=True), ("AR_ADAPTIVE_ENTROPY_WAVE", "AR_ADAPTIVE_RENAME_FANOUT"), True),
    AdaptiveActionCase("AR-ACT-20", "Replay-resistant composite", "Duplicate event delivery cannot inflate a destructive process-tree score.", lambda: [*_events(10, entropy=True, rename=True, delete=True), *[replace(item) for item in _events(10, entropy=True, rename=True, delete=True)]], ("AR_ADAPTIVE_ENTROPY_WAVE", "AR_ADAPTIVE_RENAME_FANOUT", "AR_ADAPTIVE_DELETION_FANOUT"), True),
)


def run_adaptive_action_suite(selected_ids: set[str] | None = None) -> dict[str, Any]:
    known = {case.case_id for case in ACTION_CASES}
    selected = known if selected_ids is None else {str(item) for item in selected_ids}
    unknown = selected - known
    if unknown:
        raise ValueError(f"Unknown adaptive action test IDs: {', '.join(sorted(unknown))}")
    results: list[dict[str, Any]] = []
    for case in ACTION_CASES:
        if case.case_id not in selected:
            continue
        detector = AdaptiveRansomwareDetector()
        assessment = None
        for event in case.build_events():
            assessment = detector.ingest(event)
        if assessment is None:
            raise RuntimeError(f"adaptive action case generated no events: {case.case_id}")
        required = set(case.required_reason_codes)
        passed = (
            required.issubset(assessment.reason_codes)
            and assessment.decision.automatic_response_eligible is case.automatic_response_expected
            and assessment.telemetry_coverage == case.expected_coverage
        )
        results.append({
            **case.metadata(),
            "result": "PASS" if passed else "FAIL",
            "passed": passed,
            "actual_score": assessment.decision.score,
            "actual_automatic_response_eligible": assessment.decision.automatic_response_eligible,
            "actual_coverage": assessment.telemetry_coverage,
            "reason_codes": list(assessment.reason_codes),
            "window_evidence": assessment.window_evidence,
            "duplicate_events_rejected": detector.duplicate_events,
            "automatic_containment_performed": assessment.automatic_containment_performed,
        })
    report: dict[str, Any] = {
        "operation": "adaptive_ransomware_action_suite",
        "suite_version": SUITE_VERSION,
        "model_version": MODEL_VERSION,
        "case_count": len(results),
        "passed_count": sum(item["passed"] for item in results),
        "failed_count": sum(not item["passed"] for item in results),
        "all_passed": all(item["passed"] for item in results),
        "results": results,
        "safety": {
            "filesystem_writes": False, "commands_executed": False,
            "processes_spawned": False, "network_access": False,
            "containment_performed": False, "malware_samples_used": False,
        },
        "qualification": "These metadata-only tests validate action correlation, not live sensor delivery or containment.",
    }
    report["report_sha256"] = hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest()
    return report


__all__ = ["ACTION_CASES", "SUITE_VERSION", "AdaptiveActionCase", "run_adaptive_action_suite"]
