from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path

from mac_audit_agent.not_signed.models import ProcessRecord
from mac_audit_agent.system_application_control import (
    CRITICAL_BUNDLE_IDS,
    CRITICAL_NAMES,
    DependencyImpact,
    SYSTEM_QUARANTINE,
    SystemApplicationControlPlan,
    execute_system_application_control,
)


def _load_plan(path: Path) -> SystemApplicationControlPlan:
    info = path.stat()
    invoking_uid = int(os.environ.get("SUDO_UID", "-1"))
    if os.geteuid() != 0 or invoking_uid < 0:
        raise PermissionError("Run this reviewed system-application action through sudo from the logged-in administrator account.")
    if info.st_uid != invoking_uid or stat.S_IMODE(info.st_mode) & 0o077:
        raise PermissionError("The pending plan must be owned by the invoking user and mode 0600.")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("Unsupported system-application control plan.")
    raw = payload["plan"]
    processes = tuple(ProcessRecord(**{**value, "executable_path": Path(value["executable_path"])}) for value in raw.get("processes", []))
    impacts = tuple(DependencyImpact(**value) for value in raw.get("dependency_impacts", []))
    values = dict(raw)
    values["processes"] = processes
    values["dependency_impacts"] = impacts
    values["persistence_paths"] = tuple(values.get("persistence_paths", ()))
    values["warnings"] = tuple(values.get("warnings", ()))
    plan = SystemApplicationControlPlan(**values)
    if not plan.allowed or not plan.administrator_active:
        raise PermissionError("The plan was not approved for administrator execution.")
    source = Path(plan.application_path)
    expected_quarantine = SYSTEM_QUARANTINE / f"{plan.item_id}-{source.name}"
    if plan.bundle_identifier in CRITICAL_BUNDLE_IDS or plan.display_name in CRITICAL_NAMES:
        raise PermissionError("Critical macOS applications cannot be removed by this workflow.")
    if Path(plan.quarantine_path) != expected_quarantine:
        raise PermissionError("The quarantine destination is outside the fixed MSAA system quarantine.")
    return plan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Execute one reviewed MSAA /Applications quarantine plan.")
    parser.add_argument("--plan", required=True, type=Path)
    args = parser.parse_args(argv)
    plan = _load_plan(args.plan)
    receipt = execute_system_application_control(plan)
    print(json.dumps(receipt.to_dict(), indent=2, sort_keys=True))
    args.plan.unlink(missing_ok=True)
    return 0 if receipt.status == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
