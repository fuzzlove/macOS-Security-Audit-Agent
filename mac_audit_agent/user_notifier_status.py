from __future__ import annotations

from pathlib import Path
from typing import Any

from mac_audit_agent.user_notifier_installer import UserNotifierStatus, get_user_notifier_status as _installer_status


def canonical_user_notifier_status(*, db_path: Path | str | None = None) -> UserNotifierStatus:
    status = _installer_status(db_path=Path(db_path).expanduser() if db_path else None)
    if status.loaded and status.running:
        status.install_status = "loaded_running"
        status.last_error = ""
    elif status.loaded:
        status.install_status = "loaded_not_running"
    return status


def status_to_runtime_values(status: UserNotifierStatus) -> dict[str, Any]:
    return {
        "user_notifier_install_status": status.install_status,
        "user_notifier_loaded": "1" if status.loaded else "0",
        "user_notifier_running": "1" if status.running else "0",
        "user_notifier_launchctl_domain": status.launchctl_domain,
        "user_notifier_plist_path": status.plist_path,
        "user_notifier_program_arguments": " ".join(status.program_arguments or []),
        "user_notifier_last_error": status.last_error,
        "user_notifier_process_pid": status.process_pid,
        "user_notifier_db_path": status.db_path,
        "user_notifier_stdout_path": status.stdout_path,
        "user_notifier_stderr_path": status.stderr_path,
        "user_notifier_runtime_manifest_path": status.runtime_manifest_path,
        "user_notifier_runtime_manifest_exists": status.runtime_manifest_exists,
        "user_notifier_status_source": "live_launchctl_process_plist",
    }


__all__ = ["canonical_user_notifier_status", "status_to_runtime_values"]
