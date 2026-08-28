from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .installer import ActiveProtectionInstallOptions, ActiveProtectionInstallResult, install_active_protection
from .status import resolve_active_protection_status


@dataclass(frozen=True)
class ActiveProtectionRepairOptions:
    mode: str = "protected"
    repair_system_daemon: bool = True
    repair_user_notifier: bool = True
    repair_settings_sync: bool = True
    verify: bool = True
    verbose: bool = False
    target_uid: int | None = None
    test_root: Path | None = None
    target_user: str | None = None
    target_gid: int | None = None
    target_home: Path | None = None


def repair_active_protection(options: ActiveProtectionRepairOptions) -> ActiveProtectionInstallResult:
    if options.test_root is None:
        current = resolve_active_protection_status()
        if current.status == "not_installed":
            result = install_active_protection(ActiveProtectionInstallOptions(mode=options.mode, with_system_daemon=True, with_user_notifier=options.repair_user_notifier, apply_current_settings=options.repair_settings_sync, verify=options.verify, verbose=options.verbose, target_uid=options.target_uid, operation_kind="repair", target_user=options.target_user, target_gid=options.target_gid, target_home=options.target_home))
            result.actions_taken.insert(0, "repair detected missing installation and offered/performed install")
            return result
    result = install_active_protection(ActiveProtectionInstallOptions(mode=options.mode, with_system_daemon=options.repair_system_daemon or options.repair_settings_sync, with_user_notifier=options.repair_user_notifier or options.repair_settings_sync, apply_current_settings=options.repair_settings_sync, verify=options.verify, verbose=options.verbose, target_uid=options.target_uid, test_root=options.test_root, operation_kind="repair", target_user=options.target_user, target_gid=options.target_gid, target_home=options.target_home))
    result.actions_taken.insert(0, "idempotent active-protection repair")
    return result


__all__ = ["ActiveProtectionRepairOptions", "repair_active_protection"]
