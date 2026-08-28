from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.telemetry.manager import manager_for


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="msaa telemetry", description="Local, privacy-conscious MSAA Behavioral Telemetry.")
    parser.add_argument("command", choices=["status", "summary", "anomalies", "baseline", "export", "doctor"])
    parser.add_argument("--db", type=Path, default=Path.home() / ".mac_audit_agent.sqlite3")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--since", default="24h", help="Lookback such as 1h, 24h, 7d, or 30d.")
    parser.add_argument("--user", default=None, help="Stable internal user reference; display names are not accepted.")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--rebuild", action="store_true", help="Create a new version boundary and rebuild the baseline.")
    parser.add_argument("--reason", default="operator-requested baseline rebuild")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    database = AuditDatabase(args.db.expanduser())
    try:
        manager = manager_for(database, autostart=False)
        if args.command == "status":
            payload = manager.health()
        elif args.command == "summary":
            payload = manager.summary(hours=max(1, int(_duration(args.since).total_seconds() // 3600)))
        elif args.command == "anomalies":
            payload = {
                "since": _since(args.since),
                "anomalies": manager.repository.list_anomalies(since=_since(args.since), limit=5000),
            }
        elif args.command == "baseline":
            rebuild = manager.rebuild_baseline(actor="telemetry_cli", reason=args.reason) if args.rebuild else None
            payload = {
                "version": manager.repository.latest_baseline_version(),
                "user_ref": args.user,
                "rebuild": rebuild,
                "baselines": manager.repository.list_baselines(user_ref=args.user, limit=5000),
            }
        elif args.command == "doctor":
            payload = manager.doctor()
        else:
            payload = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "since": _since(args.since),
                "summary": manager.summary(hours=max(1, int(_duration(args.since).total_seconds() // 3600))),
                "buckets": [item.to_dict() for item in manager.repository.list_buckets(since=_since(args.since), limit=20_000)],
                "anomalies": manager.repository.list_anomalies(since=_since(args.since), limit=5000),
                "incidents": manager.repository.list_incidents(since=_since(args.since), limit=5000),
                "privacy_note": "No keystrokes, clipboard contents, document contents, messages, or browsing contents are included.",
            }
            if args.output:
                _write_json(args.output.expanduser(), payload)
                payload = {"exported": str(args.output.expanduser()), "since": payload["since"]}
        if args.json or args.command in {"anomalies", "baseline", "export", "doctor"}:
            print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        else:
            _print_human(args.command, payload)
        return 0 if str(payload.get("status", "PASS")).upper() not in {"FAIL", "DEGRADED"} else 1
    finally:
        database.close()


def _duration(value: str) -> timedelta:
    text = str(value or "24h").strip().lower()
    if len(text) < 2 or text[-1] not in {"m", "h", "d"} or not text[:-1].isdigit():
        raise ValueError("--since must use a bounded duration such as 30m, 24h, or 7d")
    number = int(text[:-1])
    if not 1 <= number <= 3650:
        raise ValueError("--since duration is outside the supported range")
    return {"m": timedelta(minutes=number), "h": timedelta(hours=number), "d": timedelta(days=number)}[text[-1]]


def _since(value: str) -> str:
    return (datetime.now(timezone.utc) - _duration(value)).isoformat()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, (json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n").encode("utf-8"))
    finally:
        os.close(descriptor)


def _print_human(command: str, payload: dict) -> None:
    if command == "status":
        print(f"Behavioral Telemetry: {payload.get('state', 'UNKNOWN')}")
        print(f"Queue: {payload.get('queue_depth', 0)}/{payload.get('queue_capacity', 0)}")
        print(f"Events received/aggregated: {payload.get('events_received', 0)}/{payload.get('events_aggregated', 0)}")
        print(f"Last analysis: {payload.get('last_analysis') or 'not yet'}")
    else:
        print(f"Behavioral state: {payload.get('state', 'UNKNOWN')}")
        print(f"Baseline: {payload.get('baseline_status', 'UNKNOWN')} v{payload.get('baseline_version', 0)}")
        print(f"Anomalies: {payload.get('anomalies_today', 0)}; high risk: {payload.get('high_risk_anomalies', 0)}")


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main"]
