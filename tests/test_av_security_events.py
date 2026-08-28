from __future__ import annotations

import json

from mac_audit_agent.native_event_bridge import (
    NativeEventFrame,
    native_event_frame_to_event,
    native_event_supported_types,
    normalize_native_event_type,
)


def test_native_microphone_alias_becomes_confirmed_security_event() -> None:
    frame = NativeEventFrame.from_payload(
        {
            "event_type": "audio_capture_started",
            "source": "coreaudio_device_listener",
            "severity": "info",
            "confidence": "high",
            "process_name": "ExampleCall",
            "pid": 4242,
            "process_signing_id": "com.example.call",
            "evidence": {"device_id": "builtin-mic", "device_name": "Built-in Microphone"},
        }
    )

    event = native_event_frame_to_event(frame)

    assert event.event_type == "microphone_activity_confirmed"
    assert event.severity == "high"
    assert event.related_pid == 4242
    assert json.loads(event.metadata_json)["attribution_status"] == "attributed"


def test_locked_camera_start_is_critical_even_without_attribution() -> None:
    event = native_event_frame_to_event(
        NativeEventFrame.from_payload(
            {
                "event_type": "camera_on",
                "source": "cmio_device_listener",
                "evidence": {"device_id": "camera-1", "screen_locked": True},
            }
        )
    )

    metadata = json.loads(event.metadata_json)
    assert event.event_type == "camera_activity_confirmed"
    assert event.severity == "critical"
    assert metadata["attribution_status"] == "unattributed"
    assert "locked or idle" in metadata["suspicious_context"]


def test_external_or_virtual_capture_device_is_high_priority() -> None:
    event = native_event_frame_to_event(
        NativeEventFrame.from_payload(
            {
                "event_type": "av_device_connected",
                "source": "avfoundation_device_listener",
                "evidence": {"media_type": "video", "virtual": True, "device_name": "Unknown Camera"},
            }
        )
    )

    assert event.event_type == "capture_device_connected"
    assert event.severity == "high"
    assert "capture_device_connected" in native_event_supported_types()
    assert normalize_native_event_type("microphone_off") == "microphone_activity_stopped"
