from __future__ import annotations

import pytest

from mac_audit_agent.anti_ransomware.adaptive_detector import (
    MODEL_VERSION,
    AdaptiveDetectionPolicy,
    AdaptiveMutationEvent,
    AdaptiveRansomwareDetector,
    ProcessTrustContext,
    run_adaptive_detector_demo,
)
from mac_audit_agent.anti_ransomware.health import RuntimeEvidence, source_health


def _event(number: int, **changes: object) -> AdaptiveMutationEvent:
    values: dict[str, object] = {
        "event_id": f"event-{number}",
        "monotonic_time": 100.0 + number,
        "process_key": "process-1",
        "tree_key": "tree-1",
        "path_token": f"path-{number}",
        "directory_token": f"directory-{number % 3}",
        "volume_token": "volume-1",
        "operation": "modified",
        "bytes_changed": 8 * 1024 * 1024,
        "expected_events_per_30s": 1.0,
        "trust": ProcessTrustContext(
            signing_state="UNSIGNED", first_seen=True,
            executable_location="TEMPORARY",
        ),
    }
    values.update(changes)
    return AdaptiveMutationEvent(**values)


def test_unsigned_status_alone_does_not_create_ransomware_verdict() -> None:
    result = AdaptiveRansomwareDetector().ingest(_event(1, bytes_changed=10))
    assert result.decision.score == 0
    assert "AR_ADAPTIVE_UNTRUSTED_PROCESS_CONTEXT" not in result.reason_codes
    assert result.automatic_containment_performed is False


def test_distinct_entropy_wave_uses_behavior_then_trust_as_context() -> None:
    detector = AdaptiveRansomwareDetector()
    result = None
    for number in range(1, 6):
        result = detector.ingest(_event(number, entropy_transition=True))
    assert result is not None
    assert "AR_ADAPTIVE_ENTROPY_WAVE" in result.reason_codes
    assert "AR_ADAPTIVE_UNTRUSTED_PROCESS_CONTEXT" in result.reason_codes
    assert result.window_evidence["entropy_transition_files"] == 5
    assert result.decision.score == 85
    assert result.decision.automatic_response_eligible is False


def test_multi_signal_unsigned_process_chain_is_eligible_but_not_contained() -> None:
    detector = AdaptiveRansomwareDetector()
    result = None
    for number in range(1, 11):
        result = detector.ingest(_event(
            number,
            entropy_transition=True,
            extension_changed=True,
            renamed_over_original=True,
            original_deleted=True,
            ransom_note_pattern=number == 10,
            volume_token=f"volume-{number % 2}",
        ))
    assert result is not None
    assert result.decision.score == 100
    assert result.decision.automatic_response_eligible is True
    assert result.automatic_containment_performed is False
    assert {
        "AR_ADAPTIVE_ENTROPY_WAVE", "AR_ADAPTIVE_RENAME_FANOUT",
        "AR_ADAPTIVE_DELETION_FANOUT", "AR_ADAPTIVE_DIRECTORY_SPREAD",
        "AR_ADAPTIVE_VOLUME_SPREAD", "AR_ADAPTIVE_RATE_DEVIATION",
        "AR_ADAPTIVE_NOTE_SEQUENCE",
    } <= set(result.reason_codes)


def test_validly_signed_process_is_still_detected_from_behavior() -> None:
    detector = AdaptiveRansomwareDetector()
    trust = ProcessTrustContext(signing_state="DEVELOPER_ID", notarized=True)
    result = None
    for number in range(1, 7):
        result = detector.ingest(_event(number, entropy_transition=True, trust=trust))
    assert result is not None
    assert "AR_ADAPTIVE_ENTROPY_WAVE" in result.reason_codes
    assert "AR_ADAPTIVE_UNTRUSTED_PROCESS_CONTEXT" not in result.reason_codes


def test_partial_sensor_coverage_prevents_automatic_response() -> None:
    detector = AdaptiveRansomwareDetector()
    result = None
    for number in range(1, 11):
        result = detector.ingest(_event(
            number, entropy_transition=True, extension_changed=True,
            original_deleted=True, canary_modified=number == 10,
            telemetry_complete=False,
        ))
    assert result is not None
    assert result.decision.score == 100
    assert result.telemetry_coverage == "PARTIAL"
    assert result.decision.automatic_response_eligible is False
    assert result.decision.recommended_response == "manual_review"


def test_duplicate_events_and_state_are_bounded() -> None:
    policy = AdaptiveDetectionPolicy(maximum_process_trees=1, maximum_events_per_tree=8)
    detector = AdaptiveRansomwareDetector(policy)
    first = _event(1)
    detector.ingest(first)
    duplicate = detector.ingest(first)
    assert duplicate.event_accepted is False
    assert detector.duplicate_events == 1

    for number in range(2, 20):
        detector.ingest(_event(number))
    assert detector.retained_event_count <= 8
    assert detector.evicted_events > 0


def test_invalid_unbounded_event_is_rejected() -> None:
    with pytest.raises(ValueError, match="at most 256"):
        AdaptiveRansomwareDetector().ingest(_event(1, path_token="x" * 257))


def test_adaptive_demo_exercises_six_safe_outcomes() -> None:
    report = run_adaptive_detector_demo()
    assert report["scenario_count"] == 6
    assert report["passed_count"] == 6
    assert report["failed_count"] == 0
    assert report["all_passed"] is True
    assert set(report["safety"].values()) == {False}


def test_sensor_health_reports_adaptive_engine_without_false_active_claim() -> None:
    health = source_health(evidence=RuntimeEvidence(system_engine_running=True))
    adaptive = health.sensor_details["adaptive_ransomware_detector"]
    assert adaptive["available"] is True
    assert adaptive["active"] is False
    assert adaptive["model_version"] == MODEL_VERSION
    assert adaptive["signature_independent"] is True
