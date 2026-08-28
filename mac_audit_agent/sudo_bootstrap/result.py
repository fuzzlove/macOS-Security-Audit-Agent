from __future__ import annotations

import json
import os
import secrets
import stat
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class BootstrapErrorCode(str, Enum):
    OK = "BOOTSTRAP_OK"
    PARTIAL = "BOOTSTRAP_PARTIAL"
    NO_GUI_USER = "BOOTSTRAP_NO_GUI_USER"
    INVALID_SUDO_IDENTITY = "BOOTSTRAP_INVALID_SUDO_IDENTITY"
    CONSOLE_USER_MISMATCH = "BOOTSTRAP_CONSOLE_USER_MISMATCH"
    UNSUPPORTED_PYTHON = "BOOTSTRAP_UNSUPPORTED_PYTHON"
    UNSAFE_SOURCE_RUNTIME = "BOOTSTRAP_UNSAFE_SOURCE_RUNTIME"
    RUNTIME_STAGING_FAILED = "BOOTSTRAP_RUNTIME_STAGING_FAILED"
    DAEMON_INSTALL_FAILED = "BOOTSTRAP_DAEMON_INSTALL_FAILED"
    DAEMON_REGISTRATION_FAILED = "BOOTSTRAP_DAEMON_REGISTRATION_FAILED"
    DAEMON_START_FAILED = "BOOTSTRAP_DAEMON_START_FAILED"
    DAEMON_HEARTBEAT_STALE = "BOOTSTRAP_DAEMON_HEARTBEAT_STALE"
    DAEMON_IPC_FAILED = "BOOTSTRAP_DAEMON_IPC_FAILED"
    AGENT_INSTALL_FAILED = "BOOTSTRAP_AGENT_INSTALL_FAILED"
    AGENT_WRONG_DOMAIN = "BOOTSTRAP_AGENT_WRONG_DOMAIN"
    AGENT_START_FAILED = "BOOTSTRAP_AGENT_START_FAILED"
    AGENT_HEARTBEAT_STALE = "BOOTSTRAP_AGENT_HEARTBEAT_STALE"
    PRIVILEGE_DROP_FAILED = "BOOTSTRAP_PRIVILEGE_DROP_FAILED"
    GUI_REEXEC_FAILED = "BOOTSTRAP_GUI_REEXEC_FAILED"
    EXTENSION_APPROVAL_REQUIRED = "BOOTSTRAP_EXTENSION_APPROVAL_REQUIRED"
    FULL_DISK_ACCESS_REQUIRED = "BOOTSTRAP_FULL_DISK_ACCESS_REQUIRED"


@dataclass
class BootstrapResult:
    schema_version: int = 1
    bootstrap_id: str = field(default_factory=lambda: secrets.token_hex(16))
    created_at_unix: int = field(default_factory=lambda: int(time.time()))
    started_as_root: bool = True
    invoked_through_sudo: bool = False
    invoking_user: dict[str, Any] = field(default_factory=dict)
    protected_runtime: dict[str, Any] = field(default_factory=dict)
    system_daemon: dict[str, Any] = field(default_factory=dict)
    user_agent: dict[str, Any] = field(default_factory=dict)
    endpoint_security: dict[str, Any] = field(default_factory=dict)
    privilege_drop: dict[str, Any] = field(default_factory=dict)
    python_runtimes: dict[str, Any] = field(default_factory=dict)
    errors: list[dict[str, Any]] = field(default_factory=list)
    overall_result: str = BootstrapErrorCode.PARTIAL.value
    remediation_actions: list[str] = field(default_factory=list)
    safe_to_continue_gui: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def add_error(self, code: str, message: str, component: str, *, system_error: str = "", operation: str = "", domain: str = "", label: str = "", rollback: bool = False, safe_to_continue: bool = False) -> None:
        self.errors.append({"code": code, "message": message, "component": component, "system_error": system_error[-2000:], "operation": operation, "launchd_domain": domain, "service_label": label, "rollback_occurred": rollback, "safe_to_continue_gui": safe_to_continue})

    def write_handoff(self, directory: Path, target_uid: int, target_gid: int) -> Path:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.is_symlink():
            raise OSError("bootstrap handoff directory must not be a symlink")
        os.chown(directory, target_uid, target_gid)
        os.chmod(directory, 0o700)
        path = directory / f"bootstrap-{self.bootstrap_id}.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            payload = (json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")) + "\n").encode()
            os.write(fd, payload)
            os.fsync(fd)
            os.fchown(fd, target_uid, target_gid)
        finally:
            os.close(fd)
        return path


def consume_handoff(path: Path, expected_uid: int, *, maximum_age_seconds: int = 300) -> dict[str, Any]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1024 * 1024:
            raise PermissionError("untrusted bootstrap result")
        with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as handle:
            payload = json.load(handle)
    finally:
        os.close(fd)
    if payload.get("schema_version") != 1 or time.time() - int(payload.get("created_at_unix", 0)) > maximum_age_seconds:
        raise ValueError("expired or incompatible bootstrap result")
    path.unlink()
    return payload
