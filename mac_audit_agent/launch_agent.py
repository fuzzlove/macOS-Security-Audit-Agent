from __future__ import annotations

import hashlib
import json
import os
import plistlib
import pwd
import grp
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from mac_audit_agent.models import BackgroundMonitorStatus
from mac_audit_agent.version import APP_VERSION, DATABASE_SCHEMA_VERSION, RUNTIME_MANIFEST_SCHEMA_VERSION, current_git_commit


LAUNCH_AGENT_LABEL = "com.mac-audit-agent.monitor"
LAUNCHCTL_BIN = "/bin/launchctl"
PLUTIL_BIN = "/usr/bin/plutil"
LOG_BIN = "/usr/bin/log"
MAC_AUDIT_AGENT_ENV_SCOPE = "MAC_AUDIT_AGENT_LAUNCH_SCOPE"
MAC_AUDIT_AGENT_ENV_RUNTIME_ROOT = "MAC_AUDIT_AGENT_RUNTIME_ROOT"
MAC_AUDIT_AGENT_ENV_LOG_ROOT = "MAC_AUDIT_AGENT_LOG_ROOT"
MAC_AUDIT_AGENT_ENV_DB_PATH = "MAC_AUDIT_AGENT_DB_PATH"
MAC_AUDIT_AGENT_ENV_ROLE = "MAC_AUDIT_AGENT_MONITOR_ROLE"
MONITOR_ROLE_LEGACY = "legacy"
MONITOR_ROLE_USER = "user-notifier"
MONITOR_ROLE_SYSTEM = "system-daemon"
SYSTEM_RUNTIME_ROOT = Path("/Library/Application Support/MacAuditAgent/runtime")
SYSTEM_LOG_ROOT = Path("/Library/Logs/MacAuditAgent")
SYSTEM_DB_PATH = Path("/Library/Application Support/MacAuditAgent/mac_audit_agent.sqlite3")
SYSTEM_LAUNCH_DAEMON_PATH = Path("/Library/LaunchDaemons") / f"{LAUNCH_AGENT_LABEL}.plist"


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def monitor_script_path() -> Path:
    return project_root() / "mac_audit_agent" / "monitor.py"


def launch_scope(default: str | None = None) -> str:
    scope = (os.environ.get(MAC_AUDIT_AGENT_ENV_SCOPE, "user") if default is None else default).strip().lower()
    return "system" if scope == "system" else "user"


def user_home_dir() -> Path:
    try:
        return Path(pwd.getpwuid(user_launchctl_uid()).pw_dir).expanduser()
    except (KeyError, OSError):
        return Path.home()


def runtime_root(scope: str | None = None) -> Path:
    scope = launch_scope() if scope is None else launch_scope(scope)
    if scope == "system":
        return Path(os.environ.get(MAC_AUDIT_AGENT_ENV_RUNTIME_ROOT, str(SYSTEM_RUNTIME_ROOT))).expanduser()
    return user_home_dir() / ".mac_audit_agent" / "runtime"


def runtime_package_root(scope: str | None = None) -> Path:
    if scope is None:
        return runtime_root() / "mac_audit_agent"
    return runtime_root(scope) / "mac_audit_agent"


def runtime_monitor_script_path(scope: str | None = None) -> Path:
    if scope is None:
        return runtime_package_root() / "monitor.py"
    return runtime_package_root(scope) / "monitor.py"


def monitor_log_root(scope: str | None = None) -> Path:
    scope = launch_scope() if scope is None else launch_scope(scope)
    if scope == "system":
        return Path(os.environ.get(MAC_AUDIT_AGENT_ENV_LOG_ROOT, str(SYSTEM_LOG_ROOT))).expanduser()
    return user_home_dir() / ".mac_audit_agent" / "logs"


def default_monitor_db_path(scope: str | None = None) -> Path:
    scope = launch_scope() if scope is None else launch_scope(scope)
    if scope == "system":
        return Path(os.environ.get(MAC_AUDIT_AGENT_ENV_DB_PATH, str(SYSTEM_DB_PATH))).expanduser()
    return user_home_dir() / ".mac_audit_agent.sqlite3"


def protected_monitor_manifest_path(scope: str | None = None) -> Path:
    return runtime_root(scope) / "install_manifest.json"


def _sha256_for_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha512_for_file(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_digest(payload: Any, algorithm: str = "sha512") -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    digest = hashlib.new(algorithm)
    digest.update(serialized)
    return digest.hexdigest()


def _path_owner_mode(path: Path) -> dict[str, Any]:
    stat_result = path.stat()
    uid = int(stat_result.st_uid)
    gid = int(stat_result.st_gid)
    return {
        "owner_uid": uid,
        "group_gid": gid,
        "owner_name": pwd.getpwuid(uid).pw_name,
        "group_name": grp.getgrgid(gid).gr_name,
        "mode": oct(stat.S_IMODE(stat_result.st_mode)),
        "world_writable": bool(stat_result.st_mode & stat.S_IWOTH),
    }


def _expected_lockdown_owner_mode(scope: str) -> tuple[str, str, int]:
    scope = launch_scope(scope)
    if scope == "system":
        return "root", "wheel", 0o755
    current_user = pwd.getpwuid(os.getuid())
    return current_user.pw_name, "staff", 0o755


def _manifest_digest_source(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key not in {"manifest_digest_sha512"}}


def _tracked_runtime_files(scope: str) -> list[Path]:
    root = runtime_package_root(scope)
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts and "tests" not in path.parts)


def build_protected_monitor_manifest(*, db_path: Path | None = None, scope: str = "system") -> dict[str, Any]:
    scope = launch_scope(scope)
    root = runtime_root(scope)
    package_root = runtime_package_root(scope)
    plist = default_launch_agent_paths(scope).plist_path
    manifest: dict[str, Any] = {
        "label": LAUNCH_AGENT_LABEL,
        "scope": scope,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "runtime_version": APP_VERSION,
        "build_timestamp": datetime.now(timezone.utc).isoformat(),
        "git_commit": current_git_commit(project_root()),
        "schema_version": RUNTIME_MANIFEST_SCHEMA_VERSION,
        "database_schema_version": DATABASE_SCHEMA_VERSION,
        "db_path": str(db_path or default_monitor_db_path(scope)),
        "plist_path": str(plist),
        "runtime_root": str(root),
        "runtime_package_root": str(package_root),
        "monitor_script_path": str(runtime_monitor_script_path(scope)),
        "hash_algorithm": "sha256+sha512",
        "manifest_digest_algorithm": "sha512",
        "tracked_files": {},
    }
    if plist.exists():
        try:
            manifest["plist"] = _path_owner_mode(plist)
            manifest["plist"]["sha256"] = _sha256_for_file(plist)
            manifest["plist"]["sha512"] = _sha512_for_file(plist)
        except Exception:
            manifest["plist"] = {}
    try:
        manifest["runtime_root_info"] = _path_owner_mode(root)
    except Exception:
        manifest["runtime_root_info"] = {}
    try:
        manifest["runtime_package_root_info"] = _path_owner_mode(package_root)
    except Exception:
        manifest["runtime_package_root_info"] = {}
    tracked_files: dict[str, dict[str, Any]] = {}
    for path in _tracked_runtime_files(scope):
        try:
            tracked_files[str(path.relative_to(package_root))] = {
                "sha256": _sha256_for_file(path),
                "sha512": _sha512_for_file(path),
                **_path_owner_mode(path),
            }
        except Exception:
            continue
    manifest["tracked_files"] = tracked_files
    manifest["manifest_digest_sha512"] = _canonical_digest(
        {
            key: value
            for key, value in manifest.items()
            if key not in {"manifest_digest_sha512"}
        },
        algorithm="sha512",
    )
    return manifest


def load_protected_monitor_manifest(*, scope: str = "system") -> dict[str, Any]:
    path = protected_monitor_manifest_path(scope)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def system_monitor_location_status(paths=None) -> dict[str, Any]:
    paths = paths or default_launch_agent_paths("system")
    observed = paths.plist_path
    return {
        "valid": observed == SYSTEM_LAUNCH_DAEMON_PATH,
        "expected_plist_path": str(SYSTEM_LAUNCH_DAEMON_PATH),
        "observed_plist_path": str(observed),
        "message": (
            "System monitor plist is installed in /Library/LaunchDaemons."
            if observed == SYSTEM_LAUNCH_DAEMON_PATH
            else f"System monitor plist must be installed at {SYSTEM_LAUNCH_DAEMON_PATH}, observed {observed}."
        ),
    }


def verify_protected_monitor_integrity(*, scope: str = "system") -> dict[str, Any]:
    scope = launch_scope(scope)
    paths = default_launch_agent_paths(scope)
    location_status = system_monitor_location_status(paths) if scope == "system" else {"valid": True, "message": "User monitor mode."}
    manifest = load_protected_monitor_manifest(scope=scope)
    expected = manifest or build_protected_monitor_manifest(scope=scope)
    evidence: list[str] = []
    expected_owner, expected_group, runtime_mode = _expected_lockdown_owner_mode(scope)
    expected_mode = "0o644"
    tamper_detected = False
    severity = "low"
    confidence = "low"
    observed_plist: dict[str, Any] = {}
    manifest_digest_status = "legacy" if not manifest else "not verified"
    if not location_status.get("valid"):
        evidence.append(str(location_status.get("message", "invalid system LaunchDaemon path")))
        tamper_detected = True
        severity = "critical"
        confidence = "high"
    if paths.plist_path.exists():
        try:
            observed_plist = _path_owner_mode(paths.plist_path)
        except Exception as exc:
            evidence.append(f"unable to inspect plist: {exc}")
            tamper_detected = True
            severity = "high"
            confidence = "high"
    else:
        evidence.append(f"missing plist: {paths.plist_path}")
        tamper_detected = True
        severity = "high"
        confidence = "high"
    if observed_plist:
        owner_name = f"{observed_plist.get('owner_name', '')}:{observed_plist.get('group_name', '')}"
        if observed_plist.get("owner_name") != expected_owner or observed_plist.get("group_name") != expected_group:
            evidence.append(f"plist owner mismatch: expected {expected_owner}, observed {owner_name}")
            tamper_detected = True
        if observed_plist.get("mode") != expected_mode:
            evidence.append(f"plist mode mismatch: expected {expected_mode}, observed {observed_plist.get('mode', '')}")
            tamper_detected = True
        if observed_plist.get("world_writable"):
            evidence.append("plist is world writable")
            tamper_detected = True
        if tamper_detected:
            severity = "critical"
            confidence = "high"
    runtime_root_path = runtime_root(scope)
    runtime_package_path = runtime_package_root(scope)
    lockdown_compliant = scope != "system"
    system_lockdown_ok = scope != "system"
    if scope == "system":
        system_lockdown_ok = True
        required_paths = [
            ("runtime root", runtime_root_path, "0o755"),
            ("runtime package root", runtime_package_path, "0o755"),
            ("manifest", protected_monitor_manifest_path(scope), "0o644"),
        ]
    else:
        required_paths = [("runtime root", runtime_root_path, "0o755"), ("runtime package root", runtime_package_path, "0o755")]
    for label, path, expected_path_mode in required_paths:
        if not path.exists():
            evidence.append(f"missing {label}: {path}")
            tamper_detected = True
            severity = "high"
            confidence = "high"
            continue
        try:
            observed = _path_owner_mode(path)
            if scope == "system":
                if observed.get("owner_name") != expected_owner or observed.get("group_name") != expected_group:
                    evidence.append(
                        f"{label} owner mismatch: expected {expected_owner}:{expected_group}, observed {observed.get('owner_name', '')}:{observed.get('group_name', '')}"
                    )
                    tamper_detected = True
                    system_lockdown_ok = False
                if observed.get("mode") != expected_path_mode:
                    evidence.append(f"{label} mode mismatch: expected {expected_path_mode}, observed {observed.get('mode', '')}")
                    tamper_detected = True
                    system_lockdown_ok = False
            if observed.get("world_writable"):
                evidence.append(f"{label} is world writable: {path}")
                tamper_detected = True
                severity = "critical"
                confidence = "high"
        except Exception as exc:
            evidence.append(f"unable to inspect {label}: {exc}")
            tamper_detected = True
            severity = "high"
            confidence = "high"
            if scope == "system":
                system_lockdown_ok = False
    expected_hashes = expected.get("tracked_files", {}) if isinstance(expected.get("tracked_files", {}), dict) else {}
    observed_hashes: dict[str, str] = {}
    for rel_path, details in expected_hashes.items():
        candidate = runtime_package_path / rel_path
        try:
            if candidate.exists():
                observed_sha256 = _sha256_for_file(candidate)
                observed_sha512 = _sha512_for_file(candidate)
                observed_hashes[rel_path] = observed_sha256
                expected_sha256 = str(details.get("sha256", ""))
                expected_sha512 = str(details.get("sha512", ""))
                if expected_sha256 and observed_sha256 != expected_sha256:
                    evidence.append(f"hash changed: {candidate}")
                    tamper_detected = True
                    severity = "critical"
                    confidence = "high"
                if expected_sha512 and observed_sha512 != expected_sha512:
                    evidence.append(f"strong hash changed: {candidate}")
                    tamper_detected = True
                    severity = "critical"
                    confidence = "high"
            else:
                evidence.append(f"missing tracked file: {candidate}")
                tamper_detected = True
                severity = "critical"
                confidence = "high"
        except Exception as exc:
            evidence.append(f"hash inspection failed for {candidate}: {exc}")
            tamper_detected = True
            severity = "high"
            confidence = "high"
    if manifest:
        expected_digest = str(manifest.get("manifest_digest_sha512", ""))
        if expected_digest:
            observed_digest = _canonical_digest(_manifest_digest_source(manifest), algorithm="sha512")
            manifest_digest_status = "verified" if observed_digest == expected_digest else "mismatch"
            if observed_digest != expected_digest:
                evidence.append("manifest digest changed")
                tamper_detected = True
                severity = "critical"
                confidence = "high"
        else:
            manifest_digest_status = "legacy"
    recommendation = (
        "Reinstall protected monitor from trusted copy and review recent admin and persistence changes."
        if tamper_detected
        else "Protected monitor integrity appears consistent."
    )
    if scope == "system" and observed_plist:
        lockdown_compliant = (
            system_lockdown_ok
            and observed_plist.get("owner_name") == expected_owner
            and observed_plist.get("group_name") == expected_group
            and observed_plist.get("mode") == expected_mode
            and not tamper_detected
        )
    return {
        "scope": scope,
        "protected_mode": scope == "system",
        "installed": paths.plist_path.exists(),
        "plist_path": str(paths.plist_path),
        "runtime_root": str(runtime_root_path),
        "runtime_package_root": str(runtime_package_path),
        "manifest_path": str(protected_monitor_manifest_path(scope)),
        "manifest_exists": protected_monitor_manifest_path(scope).exists(),
        "system_daemon_location": location_status,
        "expected_owner": expected_owner,
        "expected_group": expected_group,
        "expected_mode": expected_mode,
        "runtime_mode": oct(runtime_mode),
        "expected_hashes": list(expected_hashes.keys()),
        "observed_hashes": observed_hashes,
        "observed_plist": observed_plist,
        "tamper_detected": tamper_detected,
        "lockdown_compliant": lockdown_compliant,
        "manifest_digest_status": manifest_digest_status,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "recommendation": recommendation,
        "last_checked": datetime.now(timezone.utc).isoformat(),
    }


@dataclass
class LaunchAgentPaths:
    plist_path: Path
    stdout_path: Path
    stderr_path: Path


def default_launch_agent_paths(scope: str | None = None) -> LaunchAgentPaths:
    scope = launch_scope() if scope is None else launch_scope(scope)
    logs_dir = monitor_log_root(scope)
    launch_agents_dir = Path("/Library/LaunchDaemons") if scope == "system" else user_home_dir() / "Library" / "LaunchAgents"
    return LaunchAgentPaths(
        plist_path=launch_agents_dir / f"{LAUNCH_AGENT_LABEL}.plist",
        stdout_path=logs_dir / "background_monitor.stdout.log",
        stderr_path=logs_dir / "background_monitor.stderr.log",
    )


def user_launchctl_uid() -> int:
    if os.getuid() != 0:
        return os.getuid()
    sudo_uid = os.environ.get("SUDO_UID", "").strip()
    if sudo_uid.isdigit() and int(sudo_uid) > 0:
        return int(sudo_uid)
    try:
        console_uid = Path("/dev/console").stat().st_uid
        if console_uid > 0:
            return int(console_uid)
    except OSError:
        pass
    try:
        home_uid = Path.home().stat().st_uid
        if home_uid > 0:
            return int(home_uid)
    except OSError:
        pass
    return os.getuid()


def launchctl_target(scope: str | None = None) -> str:
    scope = launch_scope() if scope is None else launch_scope(scope)
    if scope == "system":
        return "system"
    return f"gui/{user_launchctl_uid()}"


def build_launch_agent_plist(
    *,
    db_path: Path,
    poll_interval_seconds: int = 15,
    python_executable: str | None = None,
    scope: str = "user",
    mode: str | None = None,
) -> dict:
    scope = launch_scope(scope)
    launch_mode = (mode or "").strip().lower()
    paths = default_launch_agent_paths(scope)
    root = runtime_root(scope)
    monitor_path = runtime_monitor_script_path(scope)
    program_arguments = [
        python_executable or "/usr/bin/python3",
        str(monitor_path),
        "--run",
    ]
    if launch_mode in {MONITOR_ROLE_USER, MONITOR_ROLE_SYSTEM}:
        program_arguments.extend(["--mode", launch_mode])
    payload = {
        "Label": LAUNCH_AGENT_LABEL,
        "ProgramArguments": program_arguments,
        "RunAtLoad": True,
        "KeepAlive": True,
        "WorkingDirectory": str(root),
        "EnvironmentVariables": {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            MAC_AUDIT_AGENT_ENV_SCOPE: scope,
            MAC_AUDIT_AGENT_ENV_RUNTIME_ROOT: str(root),
            MAC_AUDIT_AGENT_ENV_LOG_ROOT: str(monitor_log_root(scope)),
            MAC_AUDIT_AGENT_ENV_DB_PATH: str(db_path),
        },
        "StandardOutPath": str(paths.stdout_path),
        "StandardErrorPath": str(paths.stderr_path),
    }
    if launch_mode in {MONITOR_ROLE_USER, MONITOR_ROLE_SYSTEM}:
        payload["EnvironmentVariables"][MAC_AUDIT_AGENT_ENV_ROLE] = launch_mode
    if scope == "user":
        payload["ProcessType"] = "Interactive"
    return payload


def _format_command(command: list[str]) -> str:
    return " ".join(command)


PID_RE = re.compile(r"\bpid = (\d+)\b")


class LaunchAgentManager:
    def __init__(self, db_path: Path, runner=None, scope: str = "user") -> None:
        self.db_path = db_path
        self.scope = launch_scope(scope)
        self.paths = default_launch_agent_paths(self.scope)
        self.runner = runner or subprocess.run

    def _runtime_root(self) -> Path:
        return runtime_root(self.scope)

    def _runtime_package_root(self) -> Path:
        return runtime_package_root(self.scope)

    def _runtime_monitor_script_path(self) -> Path:
        return runtime_monitor_script_path(self.scope)

    def _launchctl_target(self) -> str:
        return launchctl_target(self.scope)

    def _default_monitor_role(self) -> str | None:
        if self.scope == "system":
            return MONITOR_ROLE_SYSTEM
        return MONITOR_ROLE_USER

    def _effective_db_path(self) -> Path:
        if self.scope == "system":
            return default_monitor_db_path("system")
        return self.db_path

    def _install_with_mode(self, poll_interval_seconds: int = 15, mode: str | None = None) -> Path:
        if self.scope == "system" and os.geteuid() != 0:
            raise RuntimeError("System LaunchDaemon installation requires root privileges.")
        payload = build_launch_agent_plist(db_path=self._effective_db_path(), poll_interval_seconds=poll_interval_seconds, scope=self.scope, mode=mode)
        if payload.get("Label") != LAUNCH_AGENT_LABEL:
            raise RuntimeError(f"Invalid LaunchAgent Label: expected {LAUNCH_AGENT_LABEL}, got {payload.get('Label')}")
        self._ensure_install_paths()
        self._install_runtime_files()
        self._ensure_db_path()
        self.paths.plist_path.write_bytes(plistlib.dumps(payload))
        os.chmod(self.paths.plist_path, 0o644)
        current_user = pwd.getpwuid(user_launchctl_uid() if self.scope == "user" else os.getuid())
        target_group = "wheel" if self.scope == "system" else "staff"
        target_uid = 0 if self.scope == "system" else current_user.pw_uid
        target_gid = grp.getgrnam(target_group).gr_gid
        os.chown(self.paths.plist_path, target_uid, target_gid)
        self._run([PLUTIL_BIN, "-lint", str(self.paths.plist_path)])
        if self.scope == "system":
            self._write_protected_monitor_manifest()
            self.lock_down_protected_files()
        return self.paths.plist_path

    def install(self, poll_interval_seconds: int = 15) -> Path:
        if self.scope == "system":
            return self.install_system_monitor(poll_interval_seconds=poll_interval_seconds)
        return self.install_user_notifier(poll_interval_seconds=poll_interval_seconds)

    def install_system_monitor(self, poll_interval_seconds: int = 15) -> Path:
        if self.scope != "system":
            raise RuntimeError("System monitor installation requires a system LaunchDaemon manager.")
        location_status = system_monitor_location_status(self.paths)
        if not location_status["valid"]:
            raise RuntimeError(str(location_status["message"]))
        return self._install_with_mode(poll_interval_seconds=poll_interval_seconds, mode=MONITOR_ROLE_SYSTEM)

    def install_user_notifier(self, poll_interval_seconds: int = 15) -> Path:
        if self.scope != "user":
            raise RuntimeError("User notifier installation requires a user LaunchAgent manager.")
        return self._install_with_mode(poll_interval_seconds=poll_interval_seconds, mode=MONITOR_ROLE_USER)

    def install_protected_mode(self, poll_interval_seconds: int = 15) -> Path:
        return self.install_system_monitor(poll_interval_seconds=poll_interval_seconds)

    def uninstall(self) -> None:
        if self.paths.plist_path.exists():
            self.paths.plist_path.unlink()
        manifest_path = protected_monitor_manifest_path(self.scope)
        if manifest_path.exists():
            try:
                manifest_path.unlink()
            except OSError:
                pass

    def uninstall_protected_mode(self, remove_runtime: bool = False) -> None:
        if self.scope != "system":
            raise RuntimeError("Protected Mode requires a system LaunchDaemon manager.")
        self.stop()
        self.uninstall()
        if remove_runtime:
            for candidate in [self._runtime_package_root(), self._runtime_root()]:
                if candidate.exists():
                    shutil.rmtree(candidate, ignore_errors=True)

    def _write_protected_monitor_manifest(self) -> Path:
        manifest_path = protected_monitor_manifest_path(self.scope)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest = build_protected_monitor_manifest(db_path=self._effective_db_path(), scope=self.scope)
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
        current_user = pwd.getpwuid(user_launchctl_uid() if self.scope == "user" else os.getuid())
        target_group = "wheel" if self.scope == "system" else "staff"
        target_uid = 0 if self.scope == "system" else current_user.pw_uid
        target_gid = grp.getgrnam(target_group).gr_gid
        try:
            manifest_path.chmod(0o644)
        except OSError:
            pass
        try:
            os.chown(manifest_path, target_uid, target_gid)
        except OSError:
            pass
        return manifest_path

    def lock_down_protected_files(self) -> list[str]:
        if self.scope != "system":
            raise RuntimeError("Protected file lock-down is only available for the system LaunchDaemon.")
        if os.geteuid() != 0:
            raise RuntimeError("Protected file lock-down requires root privileges.")
        notes: list[str] = []
        try:
            wheel_gid = grp.getgrnam("wheel").gr_gid
        except KeyError as exc:
            raise RuntimeError("wheel group is required for protected file lock-down.") from exc
        targets: list[tuple[Path, int]] = [
            (self._runtime_root(), 0o755),
            (self._runtime_package_root(), 0o755),
            (protected_monitor_manifest_path(self.scope), 0o644),
            (self.paths.plist_path, 0o644),
        ]
        for path in sorted(self._runtime_package_root().rglob("*")):
            if path.is_dir():
                targets.append((path, 0o755))
            elif path.is_file():
                targets.append((path, 0o755 if path.name == "monitor.py" else 0o644))
        seen: set[Path] = set()
        for path, mode in targets:
            if path in seen or not path.exists():
                continue
            seen.add(path)
            try:
                path.chmod(mode)
                os.chown(path, 0, wheel_gid)
                notes.append(f"locked down: {path} -> root:wheel {oct(mode)}")
            except OSError as exc:
                notes.append(f"lockdown failed: {path} | {exc}")
        return notes

    def verify_protected_monitor_integrity(self) -> dict[str, Any]:
        return verify_protected_monitor_integrity(scope=self.scope)

    def protected_monitor_manifest_path(self) -> Path:
        return protected_monitor_manifest_path(self.scope)

    def repair(self, poll_interval_seconds: int = 15) -> tuple[Path, list[str]]:
        notes: list[str] = []
        for command in self._bootout_commands():
            try:
                self._run(command, tolerate=self._bootout_tolerate())
                notes.append(f"ok: {_format_command(command)}")
            except Exception as exc:
                notes.append(str(exc))
        for candidate in [
            self.paths.plist_path,
            Path("/Library/LaunchAgents") / f"{LAUNCH_AGENT_LABEL}.plist",
            Path("/Library/LaunchDaemons") / f"{LAUNCH_AGENT_LABEL}.plist",
        ]:
            try:
                if candidate.exists():
                    candidate.unlink()
                    notes.append(f"removed: {candidate}")
            except OSError as exc:
                notes.append(f"remove failed: {candidate} | {exc}")
        plist_path = self._install_with_mode(poll_interval_seconds=poll_interval_seconds, mode=self._default_monitor_role())
        self.start()
        verify = self.status()
        notes.append(f"verify: loaded={verify.loaded} running={verify.running} pid={verify.process_pid}")
        return plist_path, notes

    def force_reinstall(self, poll_interval_seconds: int = 15) -> tuple[Path, list[str]]:
        notes: list[str] = []
        for command in self._bootout_commands():
            try:
                self._run(command, tolerate=self._bootout_tolerate())
                notes.append(f"ok: {_format_command(command)}")
            except Exception as exc:
                notes.append(str(exc))
        try:
            if self.paths.plist_path.exists():
                self.paths.plist_path.unlink()
                notes.append(f"removed: {self.paths.plist_path}")
        except OSError as exc:
            notes.append(f"remove failed: {self.paths.plist_path} | {exc}")
        plist_path = self._install_with_mode(poll_interval_seconds=poll_interval_seconds, mode=self._default_monitor_role())
        notes.append(f"recreated: {plist_path}")
        self.start()
        verify = self.status()
        notes.append(f"verify: loaded={verify.loaded} running={verify.running} pid={verify.process_pid}")
        return plist_path, notes

    def start(self) -> None:
        self._bootstrap_preflight()
        for command in self._bootout_commands():
            self._run(
                command,
                tolerate=self._bootout_tolerate(),
            )
        try:
            self._run([LAUNCHCTL_BIN, "bootstrap", self._launchctl_target(), str(self.paths.plist_path)], tolerate={"already bootstrapped"})
        except Exception as exc:
            launchd_tail = self._launchd_log_tail()
            message = str(exc)
            if launchd_tail:
                message = f"{message}\nlaunchd log tail:\n{launchd_tail}"
            raise RuntimeError(message) from exc
        self._run([LAUNCHCTL_BIN, "kickstart", "-k", f"{self._launchctl_target()}/{LAUNCH_AGENT_LABEL}"])

    def stop(self) -> None:
        self._run([LAUNCHCTL_BIN, "bootout", self._launchctl_target(), str(self.paths.plist_path)], tolerate=self._bootout_tolerate())

    def revert_to_user_mode(self, poll_interval_seconds: int = 15) -> Path:
        if self.scope != "system":
            raise RuntimeError("Protected Mode revert is only valid for a system LaunchDaemon manager.")
        self.uninstall_protected_mode(remove_runtime=False)
        user_manager = LaunchAgentManager(self.db_path, runner=self.runner, scope="user")
        return user_manager.install_user_notifier(poll_interval_seconds=poll_interval_seconds)

    def status(self) -> BackgroundMonitorStatus:
        installed = self.paths.plist_path.exists()
        loaded = False
        running = False
        last_error = ""
        process_pid = None
        if installed:
            command = [LAUNCHCTL_BIN, "print", f"{self._launchctl_target()}/{LAUNCH_AGENT_LABEL}"]
            result = self._run(command, check=False)
            stdout = (result.stdout or "").lower()
            loaded = result.returncode == 0
            running = result.returncode == 0 and ("state = running" in stdout or "state = waiting" in stdout)
            pid_match = PID_RE.search(result.stdout or "")
            if pid_match:
                process_pid = int(pid_match.group(1))
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "command failed").strip()
                last_error = f"Command failed: {_format_command(command)}\nstderr:\n{detail}"
        return BackgroundMonitorStatus(
            installed=installed,
            loaded=loaded,
            running=running,
            enabled=installed,
            plist_path=str(self.paths.plist_path),
            label=LAUNCH_AGENT_LABEL,
            log_path=str(self.paths.stdout_path),
            db_path=str(self.db_path),
            process_pid=process_pid,
            last_error=last_error,
            current_launchctl_domain=self._launchctl_target(),
        )

    def show_logs(self) -> str:
        return str(self.paths.stdout_path)

    def _bootstrap_preflight(self) -> None:
        self._run([PLUTIL_BIN, "-lint", str(self.paths.plist_path)])
        payload = plistlib.loads(self.paths.plist_path.read_bytes())
        program_arguments = list(payload.get("ProgramArguments", []))
        expected_program_arguments = ["/usr/bin/python3", str(self._runtime_monitor_script_path()), "--run"]
        launch_role = str(payload.get("EnvironmentVariables", {}).get(MAC_AUDIT_AGENT_ENV_ROLE, "")).strip().lower()
        if launch_role in {MONITOR_ROLE_USER, MONITOR_ROLE_SYSTEM}:
            expected_program_arguments.extend(["--mode", launch_role])
        if program_arguments != expected_program_arguments:
            raise RuntimeError(
                "LaunchAgent preflight failed: ProgramArguments must be "
                f"{expected_program_arguments}, got {program_arguments}"
            )
        working_directory = Path(str(payload.get("WorkingDirectory", ""))).expanduser()
        if "Documents" in str(working_directory) or "Desktop" in str(working_directory) or "Downloads" in str(working_directory):
            raise RuntimeError(f"LaunchAgent preflight failed: WorkingDirectory must not be inside a protected folder: {working_directory}")
        if not working_directory.exists():
            raise RuntimeError(f"LaunchAgent preflight failed: WorkingDirectory does not exist: {working_directory}")
        if working_directory != self._runtime_root():
            raise RuntimeError(
                f"LaunchAgent preflight failed: WorkingDirectory must be {self._runtime_root()}, got {working_directory}"
            )
        if self.scope == "system" and self.paths.plist_path.parent != Path("/Library/LaunchDaemons"):
            raise RuntimeError(
                f"LaunchAgent preflight failed: system LaunchDaemon plist must live in /Library/LaunchDaemons, got {self.paths.plist_path.parent}"
            )
        for log_parent in [self.paths.stdout_path.parent, self.paths.stderr_path.parent]:
            if not log_parent.exists():
                raise RuntimeError(f"LaunchAgent preflight failed: log directory does not exist: {log_parent}")
        current_uid = user_launchctl_uid() if self.scope == "user" else os.getuid()
        plist_stat = self.paths.plist_path.stat()
        mode = stat.S_IMODE(plist_stat.st_mode)
        expected_uid = 0 if self.scope == "system" else current_uid
        if plist_stat.st_uid != expected_uid:
            owner_name = pwd.getpwuid(plist_stat.st_uid).pw_name
            expected_name = "root" if self.scope == "system" else pwd.getpwuid(current_uid).pw_name
            expected_group = "wheel" if self.scope == "system" else "staff"
            raise RuntimeError(
                f"LaunchAgent preflight failed: plist owner is {owner_name}, expected {expected_name}. "
                f"Repair: sudo chown {expected_name}:{expected_group} {self.paths.plist_path}"
            )
        if mode != 0o644:
            raise RuntimeError(
                f"LaunchAgent preflight failed: plist mode is {oct(mode)}, expected 0o644. "
                f"Repair: chmod 644 {self.paths.plist_path}"
            )

    def _ensure_install_paths(self) -> None:
        current_uid = user_launchctl_uid() if self.scope == "user" else os.getuid()
        current_user = pwd.getpwuid(current_uid)
        target_group = "wheel" if self.scope == "system" else "staff"
        target_gid = grp.getgrnam(target_group).gr_gid
        target_uid = 0 if self.scope == "system" else current_uid
        for directory in [self.paths.stdout_path.parent, self.paths.plist_path.parent, self._runtime_root(), self._runtime_package_root()]:
            directory.mkdir(parents=True, exist_ok=True)
            try:
                directory.chmod(0o755)
            except OSError:
                pass
            try:
                os.chown(directory, target_uid, target_gid)
            except OSError:
                pass
            if not os.access(directory, os.W_OK):
                raise RuntimeError(
                    f"LaunchAgent path is not writable: {directory}. "
                    f"Repair: sudo chown -R {('root' if self.scope == 'system' else current_user.pw_name)}:{target_group} {directory}"
                )

    def _ensure_db_path(self) -> None:
        db_path = self._effective_db_path()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        if self.scope != "system":
            return
        try:
            admin_gid = grp.getgrnam("admin").gr_gid
        except KeyError:
            admin_gid = grp.getgrnam("wheel").gr_gid
        try:
            db_path.parent.chmod(0o775)
            os.chown(db_path.parent, 0, admin_gid)
        except OSError:
            pass

    def _install_runtime_files(self) -> None:
        source_root = project_root() / "mac_audit_agent"
        target_root = self._runtime_package_root()
        current_uid = user_launchctl_uid() if self.scope == "user" else os.getuid()
        target_group = "wheel" if self.scope == "system" else "staff"
        target_gid = grp.getgrnam(target_group).gr_gid
        target_uid = 0 if self.scope == "system" else current_uid
        shutil.copytree(
            source_root,
            target_root,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "tests"),
            copy_function=shutil.copyfile,
        )
        for path in sorted(target_root.rglob("*")):
            try:
                if path.is_dir():
                    path.chmod(0o755)
                else:
                    path.chmod(0o755 if path.name == "monitor.py" else 0o644)
            except OSError:
                pass
            try:
                os.chown(path, target_uid, target_gid)
            except OSError:
                pass
        try:
            os.chown(target_root, target_uid, target_gid)
            os.chown(self._runtime_root(), target_uid, target_gid)
        except OSError:
            pass

    def _bootout_commands(self) -> list[list[str]]:
        return [
            [LAUNCHCTL_BIN, "bootout", f"{self._launchctl_target()}/{LAUNCH_AGENT_LABEL}"],
            [LAUNCHCTL_BIN, "bootout", self._launchctl_target(), str(self.paths.plist_path)],
        ]

    def _bootout_tolerate(self) -> set[str]:
        return {
            "could not find specified service",
            "service cannot load in requested session",
            "no such process",
            "not loaded",
            "domain does not support specified action",
            "domain does not support the specified action",
            "input/output error",
        }

    def _launchd_log_tail(self) -> str:
        if not Path(LOG_BIN).exists():
            return ""
        result = self._run(
            [
                LOG_BIN,
                "show",
                "--style",
                "compact",
                "--last",
                "5m",
                "--predicate",
                'process == "launchd"',
            ],
            check=False,
        )
        content = (result.stdout or result.stderr or "").strip()
        if not content:
            return ""
        lines = content.splitlines()
        return "\n".join(lines[-30:])

    def _run(self, command: list[str], *, check: bool = True, tolerate: set[str] | None = None):
        result = self.runner(command, capture_output=True, text=True)
        tolerate = tolerate or set()
        stderr = (result.stderr or "").lower()
        stdout = (result.stdout or "").lower()
        if check and result.returncode != 0 and not any(item in stderr or item in stdout for item in tolerate):
            detail = (result.stderr or result.stdout or "command failed").strip()
            raise RuntimeError(f"Command failed: {_format_command(command)}\nstderr:\n{detail}")
        return result
