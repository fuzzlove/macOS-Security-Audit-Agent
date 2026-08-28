from __future__ import annotations

import os
import plistlib
import pwd
import stat
import subprocess
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from mac_audit_agent.sudo_bootstrap.identity import active_console_user

LAUNCHCTL = "/bin/launchctl"
PLUTIL = "/usr/bin/plutil"
LOG = "/usr/bin/log"
MONITOR_LABEL = "com.mac-audit-agent.monitor"


class LaunchdDomainType(str, Enum):
    GUI = "gui"
    SYSTEM = "system"


@dataclass(frozen=True)
class LaunchdServiceLocation:
    label: str
    plist_path: Path | None
    domain_type: LaunchdDomainType
    uid: int | None
    loaded: bool

    @property
    def domain(self) -> str:
        return f"gui/{self.uid}" if self.domain_type is LaunchdDomainType.GUI else "system"

    @property
    def service_target(self) -> str:
        return f"{self.domain}/{self.label}"


@dataclass
class LaunchdOperationResult:
    success: bool
    changed: bool
    state: str
    label: str
    error_code: str = ""
    message: str = ""
    domain: str = ""
    command: list[str] = field(default_factory=list)
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    diagnostic_excerpt: str = ""

    def to_dict(self) -> dict[str, Any]: return asdict(self)


class LaunchdServiceManager:
    def __init__(self, label: str = MONITOR_LABEL, *, runner=None, console_resolver: Callable[[], tuple[str, int] | None] = active_console_user, sleep: Callable[[float], None] = time.sleep, user_home: Path | None = None):
        if label != MONITOR_LABEL:
            raise ValueError("Only the exact MSAA monitor label is accepted")
        self.label = label
        self.runner = runner or subprocess.run
        self.console_resolver = console_resolver
        self.sleep = sleep
        self._user_home = user_home

    def console_identity(self) -> tuple[str, int, Path]:
        console = self.console_resolver()
        if not console or console[1] <= 0 or console[0] in {"root", "loginwindow", "_windowserver", "_mbsetupuser"}:
            raise RuntimeError("LAUNCHD006_INVALID_CONSOLE_USER: no active non-root graphical console user")
        record = pwd.getpwuid(console[1])
        if record.pw_name != console[0]:
            raise RuntimeError("LAUNCHD006_INVALID_CONSOLE_USER: console UID and username disagree")
        home = self._user_home or Path(record.pw_dir)
        return record.pw_name, record.pw_uid, home

    def _run(self, command: list[str], timeout: float = 8):
        try:
            return self.runner(command, capture_output=True, text=True, timeout=timeout, check=False)
        except TypeError:
            # Narrow compatibility for dependency-injected legacy test runners;
            # subprocess.run in production always receives timeout/check.
            return self.runner(command, capture_output=True, text=True)

    def _probe(self, target: str) -> tuple[bool, Any]:
        result = self._run([LAUNCHCTL, "print", target])
        return result.returncode == 0, result

    def detected_plists(self, home: Path) -> list[Path]:
        candidates = [home / "Library/LaunchAgents" / f"{self.label}.plist", Path("/Library/LaunchAgents") / f"{self.label}.plist", Path("/Library/LaunchDaemons") / f"{self.label}.plist"]
        return [path for path in candidates if path.is_file() and not path.is_symlink()]

    def detect(self) -> dict[str, Any]:
        try:
            username, uid, home = self.console_identity()
        except RuntimeError as exc:
            return {"label": self.label, "console_user": "", "console_uid": 0, "effective_uid": os.geteuid(), "expected_domain": "", "loaded_gui": False, "loaded_system": False, "detected_plists": [], "state": "INVALID_CONSOLE_USER", "error_code": "LAUNCHD006_INVALID_CONSOLE_USER", "message": str(exc)}
        loaded_gui, gui_result = self._probe(f"gui/{uid}/{self.label}")
        loaded_system, system_result = self._probe(f"system/{self.label}")
        plists = self.detected_plists(home)
        if loaded_gui and loaded_system:
            state, error = "DUPLICATE_LOADED", "LAUNCHD004_DUPLICATE_INSTALLATION"
        elif loaded_gui:
            state, error = "LOADED_GUI", ""
        elif loaded_system:
            state, error = "LOADED_SYSTEM", "LAUNCHD001_WRONG_DOMAIN"
        else:
            state, error = "ALREADY_UNLOADED", ""
        if len(plists) > 1 and not error:
            state, error = "DUPLICATE_INSTALLATION", "LAUNCHD004_DUPLICATE_INSTALLATION"
        validations = [self.validate_plist(path, uid, home) for path in plists]
        preferred = next((path for path in plists if path.parent == home / "Library/LaunchAgents"), None)
        return {"label": self.label, "console_user": username, "console_uid": uid, "effective_uid": os.geteuid(), "expected_domain": f"gui/{uid}", "loaded_gui": loaded_gui, "loaded_system": loaded_system, "detected_plists": [str(path) for path in plists], "plist_valid": bool(validations) and all(item["valid"] for item in validations), "plist_validations": validations, "program_executable_exists": all(item.get("program_executable_exists", False) for item in validations) if validations else False, "working_directory_exists": all(item.get("working_directory_exists", False) for item in validations) if validations else False, "ownership_valid": all(item.get("ownership_valid", False) for item in validations) if validations else False, "permissions_valid": all(item.get("permissions_valid", False) for item in validations) if validations else False, "recommended_bootout_target": f"gui/{uid}/{self.label}" if loaded_gui else f"system/{self.label}" if loaded_system else "", "recommended_bootstrap_target": f"gui/{uid} {preferred}" if preferred else "", "state": state, "error_code": error, "probe_exit_codes": {"gui": gui_result.returncode, "system": system_result.returncode}, "probe_stderr": {"gui": (gui_result.stderr or "")[-1000:], "system": (system_result.stderr or "")[-1000:]}}

    def validate_plist(self, path: Path, target_uid: int, home: Path) -> dict[str, Any]:
        result = {"path": str(path), "valid": False, "errors": []}
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or path.is_symlink(): result["errors"].append("not a regular non-symlink plist")
            mode = stat.S_IMODE(info.st_mode)
            expected_uid = target_uid if path.parent == home / "Library/LaunchAgents" else 0
            result["ownership_valid"] = info.st_uid == expected_uid
            result["permissions_valid"] = mode == 0o644 and not bool(mode & (stat.S_IWGRP | stat.S_IWOTH))
            payload = plistlib.loads(path.read_bytes())
            if payload.get("Label") != self.label: result["errors"].append("label mismatch")
            arguments = payload.get("ProgramArguments")
            if not isinstance(arguments, list) or not arguments or not all(isinstance(item, str) for item in arguments): result["errors"].append("ProgramArguments must be a nonempty string array")
            executable = Path(arguments[0]) if isinstance(arguments, list) and arguments else Path("")
            result["program_executable_exists"] = executable.is_absolute() and executable.exists()
            if not result["program_executable_exists"]: result["errors"].append("program executable missing or relative")
            working = Path(payload.get("WorkingDirectory", ""))
            result["working_directory_exists"] = working.is_absolute() and working.is_dir()
            if not result["working_directory_exists"]: result["errors"].append("working directory missing or relative")
            env = payload.get("EnvironmentVariables", {})
            if isinstance(env, dict) and any(any(token in key.upper() for token in ("PASSWORD", "TOKEN", "SECRET", "PRIVATE_KEY")) for key in env): result["errors"].append("secret-like environment key")
            lint = self._run([PLUTIL, "-lint", str(path)])
            if lint.returncode != 0: result["errors"].append("plutil validation failed")
            if not result["ownership_valid"]: result["errors"].append("wrong owner")
            if not result["permissions_valid"]: result["errors"].append("unsafe permissions")
            result["valid"] = not result["errors"]
        except (OSError, ValueError, plistlib.InvalidFileException) as exc:
            result["errors"].append(f"{type(exc).__name__}: {exc}")
        return result

    def stop(self, *, verify_attempts: int = 5) -> LaunchdOperationResult:
        before = self.detect()
        if before["error_code"] == "LAUNCHD006_INVALID_CONSOLE_USER":
            return LaunchdOperationResult(False, False, before["state"], self.label, before["error_code"], before["message"])
        if before["loaded_gui"] and before["loaded_system"]:
            return LaunchdOperationResult(False, False, "CONFLICT", self.label, "LAUNCHD004_DUPLICATE_INSTALLATION", "Both GUI and system services are loaded; explicit authorized repair is required.")
        if not before["loaded_gui"] and not before["loaded_system"]:
            return LaunchdOperationResult(True, False, "ALREADY_UNLOADED", self.label, message="The service is already unloaded.")
        if before["loaded_system"]:
            if os.geteuid() != 0:
                return LaunchdOperationResult(False, False, "PRIVILEGED_HELPER_REQUIRED", self.label, "LAUNCHD007_PRIVILEGED_HELPER_REQUIRED", "A true LaunchDaemon requires the existing authorized privileged workflow; MSAA will not invoke sudo.", "system")
            target = f"system/{self.label}"
        else:
            target = f"gui/{before['console_uid']}/{self.label}"
        command = [LAUNCHCTL, "bootout", target]
        operation = self._run(command)
        for _ in range(max(1, verify_attempts)):
            after = self.detect()
            still_loaded = after["loaded_system"] if target.startswith("system/") else after["loaded_gui"]
            if not still_loaded:
                return LaunchdOperationResult(True, True, "UNLOADED", self.label, message="Service unloaded and absence verified.", domain=target.rsplit("/", 1)[0], command=command, exit_code=operation.returncode, stdout=(operation.stdout or "")[-2000:], stderr=(operation.stderr or "")[-2000:])
            self.sleep(0.2)
        code = "LAUNCHD002_PERMISSION_DENIED" if operation.returncode == 1 and "operation not permitted" in (operation.stderr or "").lower() else "LAUNCHD009_BOOTOUT_VERIFICATION_FAILED"
        return LaunchdOperationResult(False, False, "STILL_LOADED", self.label, code, "Bootout did not produce a verified unloaded state.", target.rsplit("/", 1)[0], command, operation.returncode, (operation.stdout or "")[-2000:], (operation.stderr or "")[-2000:], self.launchd_log_excerpt())

    def start_user_agent(self, plist_path: Path) -> LaunchdOperationResult:
        report = self.detect()
        uid = report.get("console_uid", 0)
        if not uid: return LaunchdOperationResult(False, False, "INVALID_CONSOLE_USER", self.label, "LAUNCHD006_INVALID_CONSOLE_USER")
        _, _, home = self.console_identity()
        validation = self.validate_plist(plist_path, uid, home)
        if not validation["valid"]: return LaunchdOperationResult(False, False, "INVALID_PLIST", self.label, "LAUNCHD005_INVALID_PLIST", "; ".join(validation["errors"]))
        if report["loaded_gui"]: return LaunchdOperationResult(True, False, "ALREADY_LOADED", self.label, domain=f"gui/{uid}")
        if report["loaded_system"] or len(report["detected_plists"]) > 1: return LaunchdOperationResult(False, False, "CONFLICT", self.label, report["error_code"] or "LAUNCHD004_DUPLICATE_INSTALLATION")
        command = [LAUNCHCTL, "bootstrap", f"gui/{uid}", str(plist_path)]
        loaded = self._run(command)
        if loaded.returncode != 0: return LaunchdOperationResult(False, False, "BOOTSTRAP_FAILED", self.label, "LAUNCHD008_BOOTOUT_FAILED", "LaunchAgent bootstrap failed.", f"gui/{uid}", command, loaded.returncode, loaded.stdout[-2000:], loaded.stderr[-2000:])
        self._run([LAUNCHCTL, "kickstart", "-k", f"gui/{uid}/{self.label}"])
        verified, _ = self._probe(f"gui/{uid}/{self.label}")
        return LaunchdOperationResult(verified, verified, "LOADED" if verified else "BOOTSTRAP_VERIFICATION_FAILED", self.label, "" if verified else "LAUNCHD009_BOOTOUT_VERIFICATION_FAILED", domain=f"gui/{uid}", command=command)

    def launchd_log_excerpt(self) -> str:
        command = [LOG, "show", "--last", "5m", "--style", "compact", "--predicate", 'process == "launchd"']
        result = self._run(command, timeout=10)
        lines = [line for line in (result.stdout or "").splitlines() if self.label in line]
        return "\n".join(lines[-50:])[-8000:]
