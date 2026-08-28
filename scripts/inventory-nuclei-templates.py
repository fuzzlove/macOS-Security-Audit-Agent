#!/usr/bin/env python3
"""Print a non-executing JSON inventory of all YAML bundled with upstream Nuclei."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from mac_audit_agent.vulnerability_scanner.loader import inventory_templates


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default="nuclei")
    parser.add_argument("--output")
    args = parser.parse_args()
    payload = {"schema": "msaa.vulnerability-template-inventory.v1", "source": str(Path(args.root)), "templates": inventory_templates(args.root)}
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.output: Path(args.output).write_text(text + "\n", encoding="utf-8")
    else: print(text)
    return 0


if __name__ == "__main__": raise SystemExit(main())
