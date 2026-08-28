"""Machine-readable and operator-facing Sensor Health CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .diagnostics import diagnostics_payload, export_diagnostics
from .manager import default_coordinator


def _default_database() -> Path:
    system = Path("/Library/Application Support/MacAuditAgent/mac_audit_agent.sqlite3")
    return system if system.is_file() else Path.home() / ".mac_audit_agent.sqlite3"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="msaa sensors", description="Prove MSAA sensor function, telemetry flow, coverage, and recovery state.")
    parser.add_argument("command", choices=["status", "test", "history", "dependencies", "recover", "diagnostics"])
    parser.add_argument("sensor_id", nargs="?")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--db", type=Path, default=_default_database())
    parser.add_argument("--system-db", type=Path, default=Path("/Library/Application Support/MacAuditAgent/mac_audit_agent.sqlite3"))
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--no-auto-recover", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    coordinator = default_coordinator(args.db.expanduser(), system_database=args.system_db.expanduser())
    try:
        if args.command in {"status", "test", "diagnostics"}:
            report = coordinator.run_cycle(run_self_tests=args.command == "test", auto_recover=not args.no_auto_recover and args.command != "diagnostics")
            payload: object = report.to_dict()
            if args.sensor_id:
                matching = [item for item in payload["sensors"] if item.get("sensor_id") == args.sensor_id]  # type: ignore[index]
                if not matching:
                    raise SystemExit(f"Unknown sensor: {args.sensor_id}")
                payload = matching[0]
            if args.command == "diagnostics":
                bundle = diagnostics_payload(coordinator.store, report.to_dict(), history_limit=args.limit)
                if not args.output:
                    raise SystemExit("diagnostics requires --output with .json, .html, .docx, or .xlsx")
                path = export_diagnostics(bundle, args.output.expanduser())
                payload = {"status": "exported", "path": str(path), "formats_supported": ["json", "html", "docx", "xlsx"]}
        elif args.command == "history":
            payload = {"sensor_id": args.sensor_id or "all", "history": coordinator.store.history(args.sensor_id or "", limit=args.limit)}
        elif args.command == "dependencies":
            coordinator.run_cycle(auto_recover=False)
            payload = {"dependencies": coordinator.store.dependencies()}
        else:
            if not args.sensor_id:
                raise SystemExit("recover requires a sensor_id")
            payload = coordinator.recover_sensor(args.sensor_id)
        if args.json or isinstance(payload, dict):
            print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        else:
            print(payload)
        overall = payload.get("overall_health") if isinstance(payload, dict) else None
        return 2 if overall in {"FAILED", "SEVERELY_DEGRADED"} else 1 if overall in {"DEGRADED", "UNKNOWN"} else 0
    finally:
        coordinator.store.close()


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main"]
