from __future__ import annotations

import argparse
import json
from pathlib import Path

from .components import active_protection_components
from .installer import ActiveProtectionInstallOptions, install_active_protection
from .repair import ActiveProtectionRepairOptions, repair_active_protection
from .status import resolve_active_protection_status


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m mac_audit_agent.protection", description="Headless MSAA Active Protection management.")
    sub = parser.add_subparsers(dest="command", required=True)
    doctor = sub.add_parser("doctor", help="Inspect live protection without changing the host.")
    doctor.add_argument("--json", action="store_true")
    plan = sub.add_parser("plan", help="Show every component and the recommended action without changing the host.")
    plan.add_argument("--json", action="store_true")
    install = sub.add_parser("install", help="Install the protected daemon and user notifier. Requires explicit administrator execution.")
    install.add_argument("--mode", choices=["protected", "observe", "disabled"], default="protected")
    install.add_argument("--with-system-daemon", action="store_true")
    install.add_argument("--with-user-notifier", action="store_true")
    install.add_argument("--apply-current-settings", action="store_true")
    install.add_argument("--verify", action="store_true")
    install.add_argument("--verbose", action="store_true")
    install.add_argument("--test-root", type=Path, help=argparse.SUPPRESS)
    for target_parser in (install,):
        target_parser.add_argument("--target-user")
        target_parser.add_argument("--target-uid", type=int)
        target_parser.add_argument("--target-gid", type=int)
        target_parser.add_argument("--target-home", type=Path)
    repair = sub.add_parser("repair", help="Repair installed protection without erasing events or evidence.")
    repair.add_argument("--mode", choices=["protected", "observe", "disabled"], default="protected")
    repair.add_argument("--repair-system-daemon", action="store_true")
    repair.add_argument("--repair-user-notifier", action="store_true")
    repair.add_argument("--repair-settings-sync", action="store_true")
    repair.add_argument("--verify", action="store_true")
    repair.add_argument("--verbose", action="store_true")
    repair.add_argument("--test-root", type=Path, help=argparse.SUPPRESS)
    repair.add_argument("--target-user")
    repair.add_argument("--target-uid", type=int)
    repair.add_argument("--target-gid", type=int)
    repair.add_argument("--target-home", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "doctor":
        status = resolve_active_protection_status()
        payload = {"protection_status": status.status, "missing_components": status.missing_components, "failed_components": status.failed_components, "daemon_launchctl_status": status.system_daemon, "notifier_launchctl_status": status.user_notifier, "service_watchdog_status": status.service_watchdog, "sensor_health_manager_status": status.sensor_health_manager, "active_db_status": status.active_db, "settings_alignment": status.settings_alignment, "alert_delivery_status": status.alert_delivery, "install_available": status.install_available, "repair_available": status.repair_available, "recommended_command": status.recommended_command, "first_failure_stage": status.first_failure_stage, "evidence_path": status.evidence_path, "headless_safe": True}
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return 0 if status.status == "installed_running" else 1
    if args.command == "plan":
        status = resolve_active_protection_status()
        payload = {"destructive": False, "administrator_approval_required": True, "explanation": "MSAA will install a system LaunchDaemon for protected monitoring and a user LaunchAgent for visible alerts. Events remain local. You can repair, disable, or uninstall these components later.", "components": [item.to_dict() for item in active_protection_components()], "current_status": status.to_dict(), "recommended_command": status.recommended_command}
        print(json.dumps(payload, indent=2, sort_keys=True, default=str)); return 0
    if args.command == "install":
        result = install_active_protection(ActiveProtectionInstallOptions(mode=args.mode, with_system_daemon=args.with_system_daemon, with_user_notifier=args.with_user_notifier, apply_current_settings=args.apply_current_settings, verify=args.verify, verbose=args.verbose, target_uid=args.target_uid, test_root=args.test_root, target_user=args.target_user, target_gid=args.target_gid, target_home=args.target_home))
    else:
        result = repair_active_protection(ActiveProtectionRepairOptions(mode=args.mode, repair_system_daemon=args.repair_system_daemon, repair_user_notifier=args.repair_user_notifier, repair_settings_sync=args.repair_settings_sync, verify=args.verify, verbose=args.verbose, target_uid=args.target_uid, test_root=args.test_root, target_user=args.target_user, target_gid=args.target_gid, target_home=args.target_home))
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True, default=str))
    return 0 if result.status in {"installed_running", "test_root_verified"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
