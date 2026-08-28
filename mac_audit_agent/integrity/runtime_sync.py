from __future__ import annotations

import importlib.util
import json
import os
import plistlib
import sys
from hashlib import sha256
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.authority import IntegrityAuthority
from mac_audit_agent.integrity.wrapper_adapter import IntegrityWrapperAdapter
from mac_audit_agent.version import APP_VERSION


USER_RUNTIME_ROOT = Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "runtime"
SYSTEM_RUNTIME_ROOT = Path("/Library/Application Support/MacAuditAgent/runtime")
RUNTIME_ROOT = USER_RUNTIME_ROOT
CRITICAL_RUNTIME_FILES = (
    "launch_agent.py",
    "monitor.py",
    "user_notifier.py",
    "user_notifier_installer.py",
    "integrity/authority.py",
    "integrity/core.py",
    "integrity/wrapper_adapter.py",
    "integrity/result_cache.py",
    "integrity/consumer_compare.py",
    "integrity/signed_manifest_validator.py",
    "integrity/strict_verifier.py",
    "performance/resource_budget.py",
    "performance/work_scheduler.py",
    "alerts/action_model.py",
    "runtime/command_models.py",
    "runtime/enum_compat.py",
    "ui/main_window.py",
    "operational_health.py",
)


@dataclass(slots=True)
class RuntimeSyncCheckResult:
    runtime_in_sync: bool
    repo_package_path: str
    installed_runtime_path: str
    integrity_authority_module_path: str
    wrapper_adapter_module_path: str
    python_executable: str
    pythonpath: list[str]
    package_version: str = ""
    git_commit: str = ""
    build_id: str = ""
    gui_process_module_path: str = "not_detected"
    user_notifier_executable: str = "not_installed_or_not_readable"
    daemon_executable: str = "not_installed_or_not_readable"
    stale_runtime_paths: list[str] = field(default_factory=list)
    checked_runtime_paths: list[str] = field(default_factory=list)
    recommended_fix: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_runtime_sync_check(root: Path | None = None, *, policy: str = "public_release") -> RuntimeSyncCheckResult:
    root = Path(root or Path.cwd()).resolve(strict=False)
    repo_pkg = root / "mac_audit_agent"
    runtime_roots = [USER_RUNTIME_ROOT, SYSTEM_RUNTIME_ROOT]
    authority_path = Path(importlib.util.find_spec("mac_audit_agent.integrity.authority").origin or "")
    wrapper_path = Path(importlib.util.find_spec("mac_audit_agent.integrity.wrapper_adapter").origin or "")
    stale: list[str] = []
    checked: list[str] = []
    for runtime in runtime_roots:
        for candidate in (runtime / "mac_audit_agent", runtime / "site-packages" / "mac_audit_agent"):
            if candidate.exists():
                checked.append(str(candidate))
                stale.extend(_runtime_package_drift(repo_pkg, candidate))
    runtime_in_sync = not stale
    notifier_executable = _plist_executable(
        Path.home() / "Library/LaunchAgents/com.liquidskynetworks.macauditagent.notifier.plist"
    )
    daemon_executable = _plist_executable(
        Path("/Library/LaunchDaemons/com.liquidskynetworks.macauditagent.monitor.plist")
    )
    return RuntimeSyncCheckResult(
        runtime_in_sync=runtime_in_sync,
        repo_package_path=str(repo_pkg),
        installed_runtime_path=str(USER_RUNTIME_ROOT),
        integrity_authority_module_path=str(authority_path),
        wrapper_adapter_module_path=str(wrapper_path),
        python_executable=sys.executable,
        pythonpath=os.environ.get("PYTHONPATH", "").split(os.pathsep) if os.environ.get("PYTHONPATH") else [],
        package_version=APP_VERSION,
        git_commit=_git_commit(root),
        build_id=os.environ.get("MSAA_BUILD_ID", ""),
        user_notifier_executable=notifier_executable,
        daemon_executable=daemon_executable,
        stale_runtime_paths=stale,
        checked_runtime_paths=checked,
        recommended_fix="" if runtime_in_sync else "Integrity core verifies in source tree, but installed runtime is using an older integrity wrapper. Reinstall or refresh the runtime package, restart the GUI, and restart notifier/daemon if they import MSAA runtime modules.",
    )


__all__ = ["RuntimeSyncCheckResult", "run_runtime_sync_check"]


def _runtime_package_drift(repo_pkg: Path, runtime_pkg: Path) -> list[str]:
    drift: list[str] = []
    for rel in CRITICAL_RUNTIME_FILES:
        source = repo_pkg / rel
        installed = runtime_pkg / rel
        if not installed.exists():
            drift.append(f"{installed}: missing")
            continue
        try:
            if _sha256(source) != _sha256(installed):
                drift.append(f"{installed}: differs from source")
        except OSError as exc:
            drift.append(f"{installed}: {type(exc).__name__}: {exc}")
    return drift


def _sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _plist_executable(path: Path) -> str:
    try:
        payload = plistlib.loads(path.read_bytes())
        arguments = payload.get("ProgramArguments") or []
        return str(arguments[0]) if arguments else str(payload.get("Program") or "not_declared")
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
        return "not_installed_or_not_readable"


def _git_commit(root: Path) -> str:
    import subprocess

    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True,
            capture_output=True, check=False, timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""
