from __future__ import annotations

from mac_audit_agent.keylogger_detection import EventTap, KeyloggerScanner
from mac_audit_agent.native_event_bridge import NativeEventFrame, native_event_frame_to_event, normalize_native_event_type


def test_global_unsigned_keyboard_tap_is_critical() -> None:
    scanner = KeyloggerScanner(
        tap_provider=lambda: ([EventTap(7, 4242, 0, 1 << 10, True, True)], "available"),
        process_provider=lambda: {4242: {"path": "/private/tmp/collector", "args": "/private/tmp/collector --quiet"}},
        tcc_provider=lambda: ([], "available"),
        signature_provider=lambda _path: {"valid": False, "authority": "", "team_id": "", "status": "unsigned"},
    )

    report = scanner.scan()

    finding = report.findings[0]
    assert finding.severity == "critical"
    assert finding.confidence == "high"
    assert "system-wide event tap" in finding.signals
    assert "missing or invalid code signature" in finding.signals
    assert finding.attack_techniques[0]["id"] == "T1056.001"
    assert report.threat_knowledge["attribution_warning"]
    assert finding.analytic_confidence_percent >= 90
    assert finding.false_positive_risk_percent <= 10
    assert finding.intervention_actions and finding.removal_actions and finding.remediation_actions
    assert report.accuracy_rate_percent is None
    assert report.accuracy_basis == "not_measured_no_adjudicated_outcomes"


def test_disabled_or_non_keyboard_taps_are_not_findings() -> None:
    scanner = KeyloggerScanner(
        tap_provider=lambda: (
            [EventTap(1, 10, 0, 1 << 10, False, True), EventTap(2, 20, 0, 1 << 5, True, True)],
            "available",
        ),
        process_provider=lambda: {},
        tcc_provider=lambda: ([], "available"),
        signature_provider=lambda _path: {"valid": True},
    )

    report = scanner.scan()

    assert report.event_tap_count == 0
    assert report.findings == []


def test_tcc_grant_is_exposure_not_infection() -> None:
    scanner = KeyloggerScanner(
        tap_provider=lambda: ([], "available"),
        process_provider=lambda: {},
        tcc_provider=lambda: ([{"service": "kTCCServiceListenEvent", "client": "com.example.utility", "auth_value": 2}], "available"),
        signature_provider=lambda _path: {"valid": True},
    )

    finding = scanner.scan().findings[0]

    assert finding.severity == "medium"
    assert finding.classification == "permission_exposure"
    assert finding.confidence == "medium"
    assert finding.attack_techniques[0]["relationship"] == "exposure_only"
    assert finding.attack_techniques[0]["observed"] is False
    assert finding.analytic_confidence_percent == 60
    assert finding.false_positive_risk_percent >= 75
    assert "not recommended" in finding.removal_actions[0].lower()


def test_documented_macos_malware_name_requires_corroboration() -> None:
    scanner=KeyloggerScanner(
        tap_provider=lambda:([EventTap(9,99,0,1<<10,True,True)],"available"),
        process_provider=lambda:{99:{"path":"/private/tmp/MacMa","args":"/private/tmp/MacMa --quiet"}},
        tcc_provider=lambda:([],"available"),
        signature_provider=lambda _path:{"valid":False},
    )
    finding=scanner.scan().findings[0]
    assert finding.documented_threat_context[0]["id"]=="S1016"
    assert "name match only" in finding.documented_threat_context[0]["assessment"]


def test_ransomware_and_apt_examples_are_context_not_attribution() -> None:
    report=KeyloggerScanner(tap_provider=lambda:([],"available"),process_provider=lambda:{},tcc_provider=lambda:([],"available"),signature_provider=lambda _path:{"valid":True}).scan()
    examples=report.threat_knowledge["documented_examples"]
    assert any(item["kind"]=="documented ransomware family" and item["id"]=="S0625" for item in examples)
    assert any(item["kind"]=="documented threat group" for item in examples)
    assert all("match_tokens" not in item for item in examples)


def test_native_event_tap_added_aliases_to_keylogger_security_event() -> None:
    assert normalize_native_event_type("keyboard_event_tap_added") == "possible_keylogger_detected"
    event = native_event_frame_to_event(
        NativeEventFrame.from_payload(
            {
                "event_type": "keyboard_event_tap_added",
                "source": "quartz_event_tap_sensor",
                "severity": "high",
                "confidence": "high",
                "process_name": "unknown-helper",
                "pid": 99,
                "evidence": {"global": True, "keyboard_events": True},
            }
        )
    )
    assert event.event_type == "possible_keylogger_detected"
    assert event.related_pid == 99


def test_native_frame_retains_processmonitor_identity_without_secrets() -> None:
    event = native_event_frame_to_event(
        NativeEventFrame.from_payload(
            {
                "event_type": "keyboard_event_tap_added",
                "source": "endpoint_security_sensor",
                "pid": 77,
                "responsible_pid": 12,
                "uid": 501,
                "architecture": "arm64",
                "code_signing_flags": 570425345,
                "cdhash": "abc123",
                "environment": {"PATH": "/usr/bin", "PASSWORD": "secret"},
                "evidence": {"keyboard_events": True},
            }
        )
    )
    assert '"responsible_pid": 12' in event.metadata_json
    assert '"PASSWORD": "[REDACTED]"' in event.metadata_json
    assert "secret" not in event.metadata_json
