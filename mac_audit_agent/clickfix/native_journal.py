from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from .service import ClickFixService

GENESIS = "0" * 64
FIELD_MAP = {
    "schemaVersion": "schema_version", "eventID": "event_id", "incidentID": "incident_id",
    "detectedAtUTC": "detected_at_utc", "monotonicTimestampNS": "monotonic_timestamp_ns",
    "keyCode": "key_code", "modifierFlags": "modifier_flags", "physicalEvent": "physical_event",
    "replayEvent": "replay_event", "foregroundPID": "foreground_pid", "foregroundBundleID": "foreground_bundle_id",
    "foregroundSigningIdentifier": "foreground_signing_identifier", "foregroundTeamIdentifier": "foreground_team_identifier",
    "clipboardChangeCount": "clipboard_change_count", "clipboardAccessState": "clipboard_access_state",
    "clipboardClassification": "clipboard_classification", "clipboardSHA256": "clipboard_sha256",
    "clipboardByteLength": "clipboard_byte_length", "classifierVersion": "classifier_version",
    "matchedCategories": "matched_categories", "redactedPreview": "redacted_preview", "sensorMode": "sensor_mode",
    "inputMonitoringState": "input_monitoring_state", "accessibilityState": "accessibility_state",
    "spotlightSuppressed": "spotlight_suppressed", "shortcutReplayed": "shortcut_replayed",
    "clipboardQuarantined": "clipboard_quarantined", "testEvent": "test_event",
}


class NativeJournalIntegrityError(RuntimeError): pass


def _canonical_payload_data(record: dict[str, Any]) -> bytes:
    try:
        return base64.b64decode(record["payload"], validate=True)
    except (KeyError, ValueError) as exc:
        raise NativeJournalIntegrityError("CFX014_EVIDENCE_PERSISTENCE_FAILED") from exc


def verify_native_journal(path: Path) -> list[dict[str, Any]]:
    if not path.exists(): return []
    data = path.read_bytes()
    if len(data) > 32 * 1024 * 1024: raise NativeJournalIntegrityError("CFX014_EVIDENCE_PERSISTENCE_FAILED")
    previous = GENESIS; expected_sequence = 1; records = []
    lines = data.splitlines()
    if data and not data.endswith(b"\n"):
        lines = lines[:-1]
    for raw_line in lines:
        if not raw_line: continue
        try: record = json.loads(raw_line)
        except json.JSONDecodeError as exc: raise NativeJournalIntegrityError("CFX014_EVIDENCE_PERSISTENCE_FAILED") from exc
        if int(record.get("sequence", 0)) != expected_sequence or record.get("previousDigest") != previous:
            raise NativeJournalIntegrityError("CFX014_EVIDENCE_PERSISTENCE_FAILED")
        payload = _canonical_payload_data(record)
        material = previous.encode("ascii") + str(record.get("recordType", "")).encode("ascii") + payload
        digest = hashlib.sha256(material).hexdigest()
        if digest != record.get("digest"): raise NativeJournalIntegrityError("CFX014_EVIDENCE_PERSISTENCE_FAILED")
        record["decoded_payload"] = json.loads(payload); records.append(record)
        previous = digest; expected_sequence += 1
    return records


class NativeJournalConsumer:
    def __init__(self, path: Path, service: ClickFixService) -> None:
        self.path = Path(path); self.service = service

    def consume(self) -> list[dict[str, Any]]:
        health = self.service.store.health(); last = int(health.get("native_journal_last_sequence", 0))
        outcomes = []
        records = verify_native_journal(self.path)
        for record in records:
            sequence = int(record["sequence"])
            if sequence <= last: continue
            if record.get("recordType") == "shortcut":
                native = record["decoded_payload"]
                envelope = {FIELD_MAP.get(key, key): value for key, value in native.items()}
                try: outcomes.append(self.service.ingest_shortcut(envelope))
                except Exception as exc:
                    if "UNIQUE constraint failed" not in str(exc): raise
            elif record.get("recordType") == "health":
                payload = record["decoded_payload"]
                error_code = str(payload.get("error_code", ""))
                if error_code:
                    try: self.service.store.persist_health_alert(str(record.get("recordID")), error_code, payload)
                    except Exception as exc:
                        if "UNIQUE constraint failed" not in str(exc): raise
                else:
                    # Successful native health snapshots are the authoritative
                    # bridge for the headless doctor.  The agent is a separate
                    # user-session process, so its in-memory XPC health closure
                    # is otherwise invisible to the Python/UI process.
                    self.service.store.set_health(payload)
                    active = set()
                    if not bool(payload.get("input_monitoring_granted")): active.add("CFX003_INPUT_MONITORING_DENIED")
                    if not bool(payload.get("event_tap_active")): active.add("CFX010_EVENT_TAP_DISABLED")
                    if not bool(payload.get("classifier_signature_valid")): active.add("CFX009_CLASSIFIER_SIGNATURE_INVALID")
                    self.service.store.reconcile_health_alerts(active)
            last = sequence
        self.service.store.set_health({"native_journal_last_sequence": last, "native_journal_integrity_valid": True})
        return outcomes
