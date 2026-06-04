from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mac_audit_agent.native_event_bridge import NativeEventFrame, native_event_frame_to_event, normalize_native_event_type


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Mac Audit Agent native event helper interface")
    parser.add_argument("--stdin-jsonl", action="store_true", help="Read JSON Lines native events from stdin and emit normalized JSON Lines to stdout.")
    parser.add_argument("--emit-sample", action="store_true", help="Emit a sample native event frame for integration testing.")
    parser.add_argument("--sample-type", default="lid_state_open", help="Sample native event type to emit.")
    return parser


def _emit_sample(event_type: str) -> int:
    frame = NativeEventFrame(
        event_type=event_type,
        source="native_helper_sample",
        confidence="high",
        severity="medium" if normalize_native_event_type(event_type) not in {"new_usb_device_detected", "system_moisture_detected"} else "critical",
        evidence={"note": "sample helper frame", "original_event_type": event_type},
    )
    event = native_event_frame_to_event(frame)
    sys.stdout.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
    return 0


def _stdin_jsonl() -> int:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        frame = NativeEventFrame.from_payload(payload)
        event = native_event_frame_to_event(frame)
        sys.stdout.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
        sys.stdout.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.emit_sample:
        return _emit_sample(args.sample_type)
    if args.stdin_jsonl:
        return _stdin_jsonl()
    build_parser().print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
