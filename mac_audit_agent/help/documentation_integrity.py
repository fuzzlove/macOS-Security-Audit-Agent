from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from .diagnostic_registry import DIAGNOSTIC_TOPICS, validate_diagnostic_registry


def emitted_diagnostic_codes(root: Path) -> set[str]:
    codes: set[str] = set()
    for path in root.rglob("*.py"):
        if any(part in {"tests", "__pycache__"} for part in path.parts):
            continue
        codes.update(re.findall(r"\bAR\d{3}\b", path.read_text(encoding="utf-8", errors="ignore")))
    return codes


def validate_documentation(root: Path) -> dict:
    emitted = emitted_diagnostic_codes(root / "mac_audit_agent")
    failures = validate_diagnostic_registry(emitted)
    return {"schema_version":"1.0", "registered_codes":sorted(DIAGNOSTIC_TOPICS),
        "emitted_codes":sorted(emitted), "failures":failures, "valid":not failures}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate packaged MSAA diagnostic documentation.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = validate_documentation(args.root)
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else ("Documentation integrity: PASS" if result["valid"] else f"Documentation integrity: FAIL ({len(result['failures'])})"))
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
