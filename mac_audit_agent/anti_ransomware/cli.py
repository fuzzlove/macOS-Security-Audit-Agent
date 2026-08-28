from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .adaptive_action_suite import run_adaptive_action_suite
from .adaptive_detector import run_adaptive_detector_demo
from .containment_diagnostics import containment_status
from .evidence import create_evidence_bundle
from .health import source_health
from .installation import inspect_install_offer, open_verified_installer
from .models import ProtectionMode
from .recovery import analyze_recovery_readiness
from .repair import repair_plan
from .simulation_suite import run_simulation_suite
from .simulator import run_safe_detection_validation, run_safe_simulation
from .standards_mapping import map_readiness
from .status import get_status
from .yara_validation_suite import (
    run_yara_validation_suite,
    validate_active_yara_release,
)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "containment":
        sub = argparse.ArgumentParser(prog="msaa anti-ransomware containment")
        sub.add_argument("operation", choices=["status", "doctor", "leases", "verify-cleanup"])
        sub.add_argument("--json", action="store_true")
        parsed = sub.parse_args(argv[1:])
        payload = containment_status() | {"operation": parsed.operation}
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if payload["ACTIVE_CONTAINMENT_READY"] else 1
    if argv and argv[0] == "repair":
        sub=argparse.ArgumentParser(prog="msaa anti-ransomware repair")
        sub.add_argument("--plan",action="store_true",default=True); sub.add_argument("--json",action="store_true")
        sub.parse_args(argv[1:]); print(json.dumps(repair_plan(),indent=2,sort_keys=True,default=str)); return 1
    if argv and argv[0] == "install":
        sub = argparse.ArgumentParser(prog="msaa anti-ransomware install")
        sub.add_argument("--plan", action="store_true", help="Inspect installation readiness without changing the host.")
        sub.add_argument("--package", help="Path to the signed and notarized MSAA installation package.")
        sub.add_argument("--open-installer", action="store_true", help="Open a verified package in Apple Installer for explicit administrator approval.")
        sub.add_argument("--json", action="store_true")
        parsed = sub.parse_args(argv[1:])
        if parsed.open_installer and not parsed.package:
            sub.error("--open-installer requires --package")
        payload = (
            open_verified_installer(Path(parsed.package))
            if parsed.open_installer
            else inspect_install_offer(Path(parsed.package) if parsed.package else None)
        ).to_dict()
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if payload["status"] in {"ready_to_install", "installer_opened"} else 1
    parser = argparse.ArgumentParser(prog="msaa anti-ransomware")
    parser.add_argument("command", choices=["status", "doctor", "health", "test", "simulate", "readiness", "coverage", "standards", "export-evidence"])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--safe", action="store_true")
    parser.add_argument("--no-file-destruction", action="store_true")
    parser.add_argument("--profile", default="synthetic_write_burst")
    parser.add_argument("--latest", action="store_true")
    parser.add_argument("--redact", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--mode", choices=[mode.value for mode in ProtectionMode], default=ProtectionMode.OBSERVE.value)
    args = parser.parse_args(argv)
    if args.command in {"test", "simulate"}:
        if not args.safe:
            parser.error("simulation requires --safe; MSAA exposes no unsafe ransomware simulator")
        if args.command == "simulate" and not args.no_file_destruction:
            parser.error("simulate requires --no-file-destruction")
        if args.profile not in {"synthetic_write_burst", "definition-suite", "live-fixture-suite", "yara-definition-suite", "active-yara-release", "adaptive-unsigned-suite", "adaptive-action-suite"}:
            parser.error("supported harmless profiles are synthetic_write_burst, definition-suite, live-fixture-suite, yara-definition-suite, active-yara-release, adaptive-unsigned-suite, and adaptive-action-suite")
        if args.profile == "definition-suite":
            payload = run_simulation_suite()
        elif args.profile == "live-fixture-suite":
            payload = run_safe_detection_validation()
        elif args.profile == "yara-definition-suite":
            payload = run_yara_validation_suite()
        elif args.profile == "active-yara-release":
            payload = validate_active_yara_release()
        elif args.profile == "adaptive-unsigned-suite":
            payload = run_adaptive_detector_demo()
        elif args.profile == "adaptive-action-suite":
            payload = run_adaptive_action_suite()
        else:
            payload = run_safe_simulation()
            payload.update({"profile": args.profile, "risk_state": "elevated", "synthetic": True,
                            "destructive": False, "user_files_touched": False})
    elif args.command == "status":
        payload = get_status()
    elif args.command == "readiness":
        payload = {"anti_ransomware": get_status(), "recovery": analyze_recovery_readiness(),
                   "standards": [item.to_dict() for item in map_readiness(audit_logging=True, recovery_ready=False, containment_policy=False)]}
    elif args.command == "export-evidence":
        destination = args.output or Path.cwd() / "reports" / "anti_ransomware" / "latest_evidence.json"
        payload = create_evidence_bundle(destination, detection=get_status(), redact=args.redact)
    else:
        health = source_health(ProtectionMode(args.mode))
        payload = health.to_dict() | {
            "product_area": "Anti-Ransomware",
            "production_active_protection": health.full_active_protection,
            "readiness": {"SAFE_SIMULATION_READY":health.safe_simulation_ready,"DEGRADED_OBSERVATION_READY":health.degraded_observation_ready,"ENDPOINT_SECURITY_OBSERVE_READY":health.endpoint_security_observe_ready,"ACTIVE_CONTAINMENT_READY":health.active_containment_ready,"FULL_ACTIVE_PROTECTION":health.full_active_protection},
        }
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
