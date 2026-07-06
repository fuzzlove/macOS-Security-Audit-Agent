from __future__ import annotations

import argparse
import json
from pathlib import Path

from mac_audit_agent.frameworks.source_registry import validate_sources, write_source_manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate official CMMC/NIST framework source registry.")
    parser.add_argument("--cmmc", action="store_true", help="Include CMMC sources.")
    parser.add_argument("--nist", action="store_true", help="Include NIST sources.")
    parser.add_argument("--fetch", action="store_true", help="Attempt network fetch and cache source bytes.")
    parser.add_argument("--output", type=Path, default=None, help="Optional JSON output path.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.output:
        write_source_manifest(args.output, fetch=args.fetch)
        print(args.output)
        return 0
    payload = validate_sources(fetch=args.fetch)
    selected = payload["sources"]
    if args.cmmc and not args.nist:
        selected = [item for item in selected if item.get("framework") == "CMMC"]
    elif args.nist and not args.cmmc:
        selected = [item for item in selected if item.get("framework") == "NIST"]
    payload["sources"] = selected
    payload["warnings"] = [item for item in selected if item.get("source_status") in {"stale_or_unavailable", "untrusted_source"}]
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 1 if payload["warnings"] and args.fetch else 0


if __name__ == "__main__":
    raise SystemExit(main())
