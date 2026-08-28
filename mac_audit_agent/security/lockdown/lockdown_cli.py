from __future__ import annotations

import argparse
import json
from pathlib import Path

from .lockdown_manager import LockdownManager
from .lockdown_permissions import CONFIRMATION_PHRASE, authorization
from .lockdown_policy import APPLE_DISCLAIMER, PROFILE_NAMES, PRODUCT_NAME


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="msaa lockdown", description=f"{PRODUCT_NAME}. {APPLE_DISCLAIMER}")
    parser.add_argument("command", choices=["status", "preflight", "enable", "disable", "export-report"])
    parser.add_argument("--profile", choices=sorted(PROFILE_NAMES), default="emergency")
    parser.add_argument("--operator", default="")
    parser.add_argument("--reason", default="")
    parser.add_argument("--ticket", default="")
    parser.add_argument("--confirm", default="", help=f"Exact phrase required: {CONFIRMATION_PHRASE}")
    parser.add_argument("--restore", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output", type=Path, default=Path.cwd() / "msaa_lockdown_report.json")
    parser.add_argument("--state-dir", type=Path, default=None, help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manager = LockdownManager(args.state_dir)
    if args.command == "status": payload = manager.status()
    elif args.command == "preflight": payload = manager.preflight(args.profile)
    elif args.command == "export-report": payload = {"report": str(manager.export_report(args.output))}
    else:
        auth = authorization(args.operator, args.reason, args.ticket, bool(args.confirm), args.confirm)
        if args.command == "enable": payload = manager.enable(args.profile, auth, dry_run=args.dry_run)
        else: payload = manager.disable(auth, restore=True, dry_run=args.dry_run)
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    return 0
