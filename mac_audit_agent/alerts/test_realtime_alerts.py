from __future__ import annotations

import argparse
import json
from pathlib import Path

from mac_audit_agent.alert_queue import build_diagnostic_alert_event, queue_visible_alert_for_notifier, wait_for_visible_alert_trace
from mac_audit_agent.runtime.db_path_resolver import get_active_monitor_db_path
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.user_notifier_installer import get_user_notifier_status


REQUIRED_EVENTS = [
    ("lid_opened", "high"),
    ("lid_closed", "high"),
    ("camera_activity_confirmed", "high"),
    ("camera_activity_stopped", "medium"),
    ("usb_device_connected", "high"),
    ("usb_storage_device_connected", "high"),
    ("bluetooth_device_connected", "medium"),
    ("new_dns_server_detected", "medium"),
    ("launchagent_added", "high"),
    ("protected_monitor_tamper_detected", "critical"),
    ("scan_critical_finding_detected", "critical"),
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safely test MSAA real-time bottom-right alerts through the User Alert Agent.")
    parser.add_argument("--db", type=Path, default=None)
    parser.add_argument("--preview", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--severity", default="high", choices=["info", "low", "medium", "high", "critical"])
    parser.add_argument("--event", default="")
    parser.add_argument("--all-required", action="store_true")
    parser.add_argument("--interactive", action="store_true", help="Wait for notifier render confirmation.")
    parser.add_argument("--timeout", type=float, default=5.0)
    return parser


def _event_type_for(args: argparse.Namespace) -> str:
    if args.event:
        return args.event
    if args.preview:
        return f"alert_preview_{args.severity}"
    if args.force:
        return "protected_monitor_tamper_detected" if args.severity == "critical" else "usb_device_connected"
    return "alert_preview_high"


def _run_one(db: AuditDatabase, *, event_type: str, severity: str, force: bool, timeout: float, interactive: bool) -> dict[str, object]:
    event = build_diagnostic_alert_event(
        event_type=event_type,
        severity=severity,
        source="alert_test_harness",
        evidence=f"MSAA diagnostic {severity} alert routed through the user notifier.",
    )
    queue = queue_visible_alert_for_notifier(db, event, force=force, reason="test_realtime_alerts")
    result = wait_for_visible_alert_trace(db, event.event_id, timeout_seconds=timeout) if interactive else {"visible": False, "trace": {}, "interactive": False}
    trace = result.get("trace", {}) if isinstance(result, dict) else {}
    return {
        "event_id": event.event_id,
        "event_type": event_type,
        "severity": severity,
        "queued": queue,
        "visible": bool(result.get("visible")) if isinstance(result, dict) else False,
        "render_verification_status": trace.get("render_verification_status", "not_waited" if not interactive else "unknown") if isinstance(trace, dict) else "unknown",
        "failure_stage": trace.get("failure_stage", "") if isinstance(trace, dict) else "",
        "trace": trace,
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    db_path = args.db.expanduser() if args.db else get_active_monitor_db_path(Path.home() / ".mac_audit_agent.sqlite3")
    db = AuditDatabase(db_path)
    notifier = get_user_notifier_status(db_path=db_path).to_dict()
    if not notifier.get("live_launchctl_loaded") or not notifier.get("live_launchctl_running"):
        print(json.dumps({"status": "failed", "failure_stage": "failed_notifier_not_running", "notifier": notifier}, indent=2, sort_keys=True))
        return 2
    tests = REQUIRED_EVENTS if args.all_required else [(_event_type_for(args), args.severity)]
    results = [_run_one(db, event_type=event_type, severity=severity, force=bool(args.force or args.preview), timeout=args.timeout, interactive=args.interactive) for event_type, severity in tests]
    ok = all(item.get("visible") for item in results) if args.interactive else all(item.get("queued", {}).get("stored") for item in results)
    print(json.dumps({"status": "pass" if ok else "failed", "db_path": str(db_path), "notifier": notifier, "results": results}, indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
