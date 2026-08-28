from __future__ import annotations

from pathlib import Path
from typing import Any
import importlib.util
import json
import os

from mac_audit_agent.user_notifier_installer import UserNotifierStatus, get_user_notifier_status as _installer_status


def canonical_user_notifier_status(*, db_path: Path | str | None = None) -> UserNotifierStatus:
    status = _installer_status(db_path=Path(db_path).expanduser() if db_path else None)
    if status.loaded and status.running and status.source_database_readable:
        status.install_status = "loaded_running"
        status.last_error = ""
    elif status.loaded and status.running:
        status.install_status = "loaded_unhealthy"
    elif status.loaded:
        status.install_status = "loaded_not_running"
    return status


def status_to_runtime_values(status: UserNotifierStatus) -> dict[str, Any]:
    arguments = list(status.program_arguments or [])
    executable_valid = bool(arguments and Path(arguments[0]).is_file() and os.access(arguments[0], os.X_OK))
    launch_arguments_valid = bool(arguments and not (getattr(__import__("sys"), "frozen", False) and "-m" in arguments))
    source = Path(status.db_path).expanduser() if status.db_path else Path()
    manifest_build = ""
    try:
        manifest_build = str(json.loads(Path(status.runtime_manifest_path).read_text(encoding="utf-8")).get("git_commit", ""))
    except (OSError, ValueError, TypeError):
        pass
    from mac_audit_agent.version import current_git_commit
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
        "user_notifier_live_launchctl_loaded": "1" if status.live_launchctl_loaded else "0",
        "user_notifier_live_launchctl_running": "1" if status.live_launchctl_running else "0",
        "user_notifier_live_process_pid": status.live_process_pid,
        "user_notifier_active_db_heartbeat": status.active_db_heartbeat,
        "user_notifier_active_db_heartbeat_age_seconds": status.active_db_heartbeat_age_seconds,
        "user_notifier_stdout_tail_latest_timestamp": status.stdout_tail_latest_timestamp,
        "user_notifier_stderr_tail_latest_timestamp": status.stderr_tail_latest_timestamp,
        "user_notifier_historical_stdout_heartbeat_detected": "1" if status.historical_stdout_heartbeat_detected else "0",
        "user_notifier_stale_log_evidence": "1" if status.stale_log_evidence else "0",
        "user_notifier_status_source": status.status_source,
        "user_notifier_executable_valid": "1" if executable_valid else "0",
        "user_notifier_launch_arguments_valid": "1" if launch_arguments_valid else "0",
        "user_notifier_source_readable": "1" if source.is_file() and os.access(source, os.R_OK) else "0",
        "user_notifier_source_database_readable": "1" if status.source_database_readable else "0",
        "user_notifier_source_database_integrity": status.source_database_integrity,
        "user_notifier_source_database_error": status.source_database_error,
        "user_notifier_receipt_store_writable": "1" if status.logs_writable else "0",
        "user_notifier_build_identity_aligned": "1" if manifest_build and manifest_build == current_git_commit() else "0",
        "user_notifier_current_diagnostic_event_received": "0",
        "user_notifier_render_path_available": "1" if importlib.util.find_spec("PySide6") is not None else "0",
    }


__all__ = ["canonical_user_notifier_status", "status_to_runtime_values"]
