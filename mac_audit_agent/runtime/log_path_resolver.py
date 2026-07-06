from __future__ import annotations

import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path

from mac_audit_agent.launch_agent import MONITOR_ROLE_LEGACY, MONITOR_ROLE_SYSTEM, MONITOR_ROLE_USER


@dataclass(frozen=True)
class RuntimeLogPaths:
    role: str
    monitor_mode: str
    stdout_path: Path
    stderr_path: Path
    monitor_log_path: Path | None = None

    def to_dict(self) -> dict[str, str]:
        payload = asdict(self)
        return {key: str(value) for key, value in payload.items() if value is not None}


def get_log_paths_for_role(role: str, monitor_mode: str = "") -> RuntimeLogPaths:
    normalized_role = (role or MONITOR_ROLE_LEGACY).strip().lower()
    normalized_mode = (monitor_mode or normalized_role).strip().lower()
    if normalized_role == MONITOR_ROLE_USER:
        return get_user_notifier_log_paths()
    if normalized_role == MONITOR_ROLE_SYSTEM or normalized_mode in {"system", MONITOR_ROLE_SYSTEM, "protected"}:
        return get_system_daemon_log_paths()
    return get_legacy_user_monitor_log_paths()


def get_user_notifier_log_paths() -> RuntimeLogPaths:
    root = Path.home() / "Library" / "Logs" / "MacAuditAgent"
    return RuntimeLogPaths(
        role=MONITOR_ROLE_USER,
        monitor_mode=MONITOR_ROLE_USER,
        stdout_path=root / "user_notifier.stdout.log",
        stderr_path=root / "user_notifier.stderr.log",
        monitor_log_path=None,
    )


def get_system_daemon_log_paths() -> RuntimeLogPaths:
    root = Path("/Library/Logs/MacAuditAgent")
    return RuntimeLogPaths(
        role=MONITOR_ROLE_SYSTEM,
        monitor_mode="system",
        stdout_path=root / "background_monitor.stdout.log",
        stderr_path=root / "background_monitor.stderr.log",
        monitor_log_path=root / "monitor.log",
    )


def get_legacy_user_monitor_log_paths() -> RuntimeLogPaths:
    root = Path.home() / ".mac_audit_agent" / "logs"
    return RuntimeLogPaths(
        role=MONITOR_ROLE_LEGACY,
        monitor_mode="user",
        stdout_path=root / "background_monitor.stdout.log",
        stderr_path=root / "background_monitor.stderr.log",
        monitor_log_path=root / "monitor.log",
    )


def validate_log_path_permissions(paths: RuntimeLogPaths) -> dict[str, dict[str, object]]:
    results: dict[str, dict[str, object]] = {}
    for label, path in {
        "stdout_path": paths.stdout_path,
        "stderr_path": paths.stderr_path,
        "monitor_log_path": paths.monitor_log_path,
    }.items():
        if path is None:
            continue
        results[label] = _path_permission(path)
    return results


def _path_permission(path: Path) -> dict[str, object]:
    target = path if path.exists() else path.parent
    try:
        st = target.stat()
    except OSError as exc:
        return {"path": str(path), "exists": False, "writable": False, "error": str(exc)}
    mode = stat.S_IMODE(st.st_mode)
    writable = False
    if st.st_uid == os.getuid() and mode & stat.S_IWUSR:
        writable = True
    elif st.st_gid in os.getgroups() and mode & stat.S_IWGRP:
        writable = True
    elif mode & stat.S_IWOTH:
        writable = True
    return {
        "path": str(path),
        "exists": path.exists(),
        "parent_exists": path.parent.exists(),
        "owner_uid": st.st_uid,
        "group_gid": st.st_gid,
        "mode": oct(mode),
        "writable": writable,
    }


__all__ = [
    "RuntimeLogPaths",
    "get_log_paths_for_role",
    "get_user_notifier_log_paths",
    "get_system_daemon_log_paths",
    "get_legacy_user_monitor_log_paths",
    "validate_log_path_permissions",
]
