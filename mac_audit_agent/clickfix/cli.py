from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .classifier import classify_text, evidence_hash
from .evidence import ClickFixEvidenceStore
from .health import doctor
from .models import GuardProfile
from .native_journal import NativeJournalConsumer, NativeJournalIntegrityError
from .policy import ClickFixPolicy
from .service import ClickFixService

SAFE_FIXTURE = "Quarterly security review notes for the local workstation."
CLICKFIX_FIXTURE = "printf '%s' inert-test | sh -n"  # classified only; never executed


def default_db_path() -> Path:
    configured = os.environ.get("MSAA_CLICKFIX_DB")
    if configured: return Path(configured).expanduser()
    return Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "clickfix_evidence.sqlite3"


def default_native_journal_path() -> Path:
    configured = os.environ.get("MSAA_CLICKFIX_NATIVE_JOURNAL")
    if configured: return Path(configured).expanduser()
    return Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "ClickFixGuard" / "events.jsonl"


def _consume_native_health(store: ClickFixEvidenceStore) -> None:
    service = ClickFixService(store, ClickFixPolicy.for_profile(GuardProfile.WARN))
    try:
        NativeJournalConsumer(default_native_journal_path(), service).consume()
    except NativeJournalIntegrityError as exc:
        store.set_health({"native_journal_integrity_valid": False, "native_journal_error": str(exc)})


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m mac_audit_agent.clickfix", description="Headless MSAA ClickFix Guard diagnostics")
    parser.add_argument("command", choices=("doctor", "status", "test-alert", "test-classifier", "verify-evidence"))
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument("--fixture", choices=("safe", "clickfix"), default="safe")
    parser.add_argument("--db", type=Path, default=default_db_path())
    return parser


def _synthetic_envelope() -> dict:
    text = CLICKFIX_FIXTURE; result = classify_text(text)
    return {
        "schema_version": 1, "event_id": "cfx-synthetic-" + os.urandom(12).hex(),
        "detected_at_utc": datetime.now(timezone.utc).isoformat(), "monotonic_timestamp_ns": 0,
        "key_code": 49, "modifier_flags": 0x100000, "physical_event": False, "replay_event": False,
        "foreground_bundle_id": "com.example.msaa.synthetic-test", "clipboard_access_state": "CLIPBOARD_ACCESS_GRANTED",
        "clipboard_classification": result.classification, "clipboard_sha256": evidence_hash(text),
        "clipboard_byte_length": len(text.encode()), "classifier_version": result.classifier_version,
        "confidence": result.confidence, "matched_categories": result.matched_categories,
        "redacted_preview": "SYNTHETIC CLICKFIX TEST — NO REAL INCIDENT DETECTED",
        "sensor_mode": "SYNTHETIC_TEST", "input_monitoring_state": "INPUT_MONITORING_UNKNOWN",
        "accessibility_state": "ACCESSIBILITY_UNKNOWN", "spotlight_suppressed": False,
        "test_event": True,
    }


def main(argv: Optional[list[str]] = None) -> int:
    args = _parser().parse_args(argv)
    with ClickFixEvidenceStore(args.db) as store:
        if args.command == "doctor":
            _consume_native_health(store); payload = doctor(store.health())
        elif args.command == "status":
            _consume_native_health(store); payload = doctor(store.health())
        elif args.command == "verify-evidence": payload = store.verify()
        elif args.command == "test-classifier":
            fixture = SAFE_FIXTURE if args.fixture == "safe" else CLICKFIX_FIXTURE
            result = classify_text(fixture)
            payload = {**result.__dict__, "fixture": args.fixture, "executed": False, "sha256": evidence_hash(fixture)}
        else:
            service = ClickFixService(store, ClickFixPolicy.for_profile(GuardProfile.WARN))
            payload = service.ingest_shortcut(_synthetic_envelope())
            payload.update({"banner": "SYNTHETIC CLICKFIX TEST — NO REAL INCIDENT DETECTED", "executed": False, "gui_initialized": False})
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if payload.get("valid", True) else 2
