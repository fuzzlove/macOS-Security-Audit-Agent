from __future__ import annotations

import argparse
import json
from pathlib import Path

from .evidence import EvidenceStore
from .registry import CONTROL_REGISTRY


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(prog="python -m mac_audit_agent.security_controls")
    sub=parser.add_subparsers(dest="command",required=True)
    sub.add_parser("doctor");sub.add_parser("snapshot");sub.add_parser("compare")
    verify=sub.add_parser("verify-evidence");verify.add_argument("--database",type=Path,required=True)
    args=parser.parse_args(argv)
    if args.command=="doctor":
        print(json.dumps({"mode":"OBSERVATION_ONLY","endpoint_security":"not_connected","fsevents":"not_connected","polling":"available","controls":len(CONTROL_REGISTRY),"message":"Native sensors must report their real status; no connectivity is simulated."},indent=2));return 1
    if args.command=="snapshot":
        print(json.dumps({"schema_version":1,"controls":[{"control_id":item.control_id,"category":item.category,"status":"collector_not_invoked"} for item in CONTROL_REGISTRY.values()]},indent=2));return 0
    if args.command=="compare":
        print(json.dumps({"error_code":"BASELINE_INPUT_REQUIRED","message":"Use the application monitor with persisted before-and-after snapshots."}));return 2
    with EvidenceStore(args.database) as store: result=store.verify_chain()
    print(json.dumps(result,indent=2));return 0 if result["valid"] else 4


if __name__=="__main__":raise SystemExit(main())
