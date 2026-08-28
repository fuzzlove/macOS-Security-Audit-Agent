#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, sqlite3, sys
from dataclasses import asdict
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from mac_audit_agent.database_recovery import quick_check, recover_system_monitor_database
from mac_audit_agent.storage import SYSTEM_MONITOR_DB_PATH

def main(argv=None)->int:
    parser=argparse.ArgumentParser(description="Preserve, recover, validate, and restart the MSAA system monitor database.")
    parser.add_argument("--check",action="store_true",help="Read-only integrity check; does not require administrator access.")
    parser.add_argument("--database",type=Path,default=SYSTEM_MONITOR_DB_PATH)
    parser.add_argument("--evidence-root",type=Path)
    parser.add_argument("--no-launchd",action="store_true",help="Test/local recovery only; do not change launchd state.")
    args=parser.parse_args(argv)
    if args.check:
        try:print(json.dumps({"database":str(args.database),"quick_check":quick_check(args.database)},sort_keys=True));return 0
        except (OSError,sqlite3.Error) as exc:
            print(json.dumps({"database":str(args.database),"quick_check":"failed","error":type(exc).__name__}),file=sys.stderr);return 2
    try:receipt=recover_system_monitor_database(source=args.database,evidence_root=args.evidence_root,manage_launchd=not args.no_launchd)
    except Exception as exc:
        print(json.dumps({"status":"failed","error":type(exc).__name__,"message":str(exc)[:500]},sort_keys=True),file=sys.stderr);return 1
    print(json.dumps({"status":"recovered",**asdict(receipt)},sort_keys=True));return 0

if __name__=="__main__":
    raise SystemExit(main())
