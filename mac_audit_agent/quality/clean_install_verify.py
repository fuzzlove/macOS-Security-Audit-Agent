from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mac_audit_agent.cli import _verify_clean_install
from mac_audit_agent.storage import AuditDatabase


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify MSAA clean wheel installation in a temporary venv.")
    parser.add_argument("--db", type=Path, default=Path.home() / ".mac_audit_agent.sqlite3", help="Database path used to store clean install evidence.")
    parser.add_argument("--python", type=Path, default=Path(sys.executable), help="Python 3.10-3.13 interpreter to create the clean venv.")
    parser.add_argument("--wheel", type=Path, default=None, help="Wheel path to install. Defaults to newest dist/*.whl.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = _verify_clean_install(AuditDatabase(args.db.expanduser()), python_executable=args.python.expanduser(), wheel_path=args.wheel.expanduser() if args.wheel else None)
    print(json.dumps(payload, indent=2, sort_keys=True))
    failed = [stage for stage in payload.get("stages", []) if str(stage.get("status", "")).upper() == "FAIL"]
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
