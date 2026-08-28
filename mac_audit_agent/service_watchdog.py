"""Integrity-gated, rate-limited repair for installed MSAA launchd jobs.

The watchdog intentionally has a fixed service inventory.  It will never adopt,
load, or restart an arbitrary plist merely because its name resembles MSAA.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import plistlib
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence
from uuid import uuid4

WATCHDOG_LABEL = "com.mac-audit-agent.service-watchdog"
WATCHDOG_PLIST_PATH = Path("/Library/LaunchDaemons") / f"{WATCHDOG_LABEL}.plist"
WATCHDOG_STATE_DIR = Path("/Library/Application Support/MacAuditAgent/watchdog")
WATCHDOG_RUN_DIR = Path("/Library/Application Support/MacAuditAgent/run")
WATCHDOG_LOG_DIR = Path("/Library/Logs/MacAuditAgent")
WATCHDOG_STATE_PATH = WATCHDOG_STATE_DIR / "state.json"
WATCHDOG_HEALTH_PATH = WATCHDOG_RUN_DIR / "service-watchdog-health.json"
WATCHDOG_AUDIT_PATH = WATCHDOG_LOG_DIR / "service-watchdog.jsonl"
WATCHDOG_LOCK_PATH = WATCHDOG_STATE_DIR / "service-watchdog.lock"
WATCHDOG_RECOVERY_REQUEST_DIR = WATCHDOG_STATE_DIR / "recovery-requests"
LAUNCHCTL = "/bin/launchctl"
CODESIGN = "/usr/bin/codesign"
PLUTIL = "/usr/bin/plutil"
PID_PATTERN = re.compile(r"\bpid = (\d+)\b")
ATTEMPT_WINDOW_SECONDS = 15 * 60
SUPPRESSION_SECONDS = 30 * 60
MAX_ATTEMPTS_PER_WINDOW = 3
HEARTBEAT_MAX_AGE_SECONDS = 180


@dataclass(frozen=True)
class ServiceSpec:
    label: str
    display_name: str
    domain: str
    plist_path: Path
    expected_uid: int
    kind: str
    expected_executable: str = ""
    expected_signing_identifier: str = ""
    required_entitlement: str = ""
    heartbeat_database: Path | None = None
    heartbeat_key: str = ""

    @property
    def target(self) -> str:
        return f"{self.domain}/{self.label}"


@dataclass(frozen=True)
class ServiceObservation:
    installed: bool
    loaded: bool
    running: bool
    pid: int | None
    heartbeat_fresh: bool | None
    heartbeat_age_seconds: float | None
    detail: str = ""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def known_service_specs(
    uid: int,
    home: Path,
    *,
    launch_daemons: Path = Path("/Library/LaunchDaemons"),
    launch_agents: Path | None = None,
) -> tuple[ServiceSpec, ...]:
    """Return the complete, fixed MSAA service allowlist.

    Callers still filter this inventory by plist existence, so optional product
    components are not silently installed by the watchdog.
    """
    agents = launch_agents or home / "Library" / "LaunchAgents"
    system = "system"
    gui = f"gui/{uid}"
    return (
        ServiceSpec(
            "com.mac-audit-agent.monitor",
            "System Monitor",
            system,
            launch_daemons / "com.mac-audit-agent.monitor.plist",
            0,
            "system_monitor",
            heartbeat_key="last_heartbeat",
        ),
        ServiceSpec(
            "com.mac-audit-agent.sensor-health",
            "Sensor Health Manager",
            system,
            launch_daemons / "com.mac-audit-agent.sensor-health.plist",
            0,
            "sensor_health",
            heartbeat_database=Path("/Library/Application Support/MacAuditAgent/mac_audit_agent.sqlite3"),
            heartbeat_key="sensor_health_manager_last_cycle",
        ),
        ServiceSpec(
            "com.fuzzlove.MacAuditAgent.EndpointSecuritySensor",
            "Endpoint Security Sensor",
            system,
            launch_daemons / "com.fuzzlove.MacAuditAgent.EndpointSecuritySensor.plist",
            0,
            "native",
            "/Library/Application Support/MacAuditAgent/bin/MSAAEndpointSecuritySensor.app/Contents/MacOS/MSAAEndpointSecuritySensor",
            expected_signing_identifier="com.fuzzlove.MacAuditAgent.EndpointSecuritySensor",
            required_entitlement="com.apple.developer.endpoint-security.client",
        ),
        ServiceSpec(
            "com.fuzzlove.MacAuditAgent.ContainmentHelper",
            "Containment Helper",
            system,
            launch_daemons / "com.fuzzlove.MacAuditAgent.ContainmentHelper.plist",
            0,
            "native",
            "/Library/Application Support/MacAuditAgent/bin/MSAAContainmentHelper",
            expected_signing_identifier="com.fuzzlove.MacAuditAgent.ContainmentHelper",
        ),
        ServiceSpec(
            "com.macos-security-audit-agent.monitor",
            "RCE Monitor",
            system,
            launch_daemons / "com.macos-security-audit-agent.monitor.plist",
            0,
            "native",
            "/Library/Application Support/MacAuditAgent/bin/msaa",
        ),
        ServiceSpec(
            "com.mac-audit-agent.user-notifier",
            "User Alert Agent",
            gui,
            agents / "com.mac-audit-agent.user-notifier.plist",
            uid,
            "user_notifier",
            heartbeat_database=home / "Library/Application Support/MacAuditAgent/alert_receipts.sqlite3",
            heartbeat_key="user_notifier_heartbeat",
        ),
        ServiceSpec(
            "com.macos-security-audit-agent.clickfix-guard",
            "ClickFix Guard",
            gui,
            agents / "com.macos-security-audit-agent.clickfix-guard.plist",
            uid,
            "native",
            str(home / "Library/Application Support/MacAuditAgent/ClickFixGuard/MSAAClickFixGuardAgent.app/Contents/MacOS/MSAAClickFixGuardAgent"),
            expected_signing_identifier="com.macos-security-audit-agent.clickfix-guard",
        ),
    )


def build_watchdog_plist(executable: str, uid: int, *, frozen: bool = False, interval_seconds: int = 60) -> dict[str, Any]:
    arguments = [executable, "--service-watchdog", "--uid", str(uid)] if frozen else [
        executable,
        "-m",
        "mac_audit_agent.service_watchdog",
        "run-once",
        "--uid",
        str(uid),
    ]
    return {
        "Label": WATCHDOG_LABEL,
        "ProgramArguments": arguments,
        "RunAtLoad": True,
        "StartInterval": max(30, int(interval_seconds)),
        "ThrottleInterval": 10,
        "ProcessType": "Background",
        "WorkingDirectory": str(WATCHDOG_STATE_DIR if frozen else Path("/Library/Application Support/MacAuditAgent/runtime")),
        "EnvironmentVariables": {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            **({} if frozen else {"PYTHONPATH": "/Library/Application Support/MacAuditAgent/runtime"}),
        },
        "StandardOutPath": str(WATCHDOG_LOG_DIR / "service-watchdog.stdout.log"),
        "StandardErrorPath": str(WATCHDOG_LOG_DIR / "service-watchdog.stderr.log"),
    }


def _atomic_json(path: Path, payload: dict[str, Any], *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def _result_text(result: Any) -> str:
    return "\n".join(part.strip() for part in (getattr(result, "stdout", ""), getattr(result, "stderr", "")) if part).strip()


def _canonical_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def request_service_recovery(
    sensor_id: str,
    reason_code: str,
    *,
    request_dir: Path = WATCHDOG_RECOVERY_REQUEST_DIR,
    requested_by: str = "sensor_health_manager",
) -> Path:
    """Submit one bounded request; only the watchdog may execute the restart."""
    allowed = {
        "endpoint_security", "ransomware_monitor", "system_monitor",
        "user_notifier", "sensor_health_manager",
    }
    reasons = {
        "PROCESS_NOT_RUNNING", "HEARTBEAT_STALE", "PROCESSING_STALL",
        "DELIVERY_STALL", "PERSISTENCE_STALL", "EVENT_STREAM_STALE",
    }
    if sensor_id not in allowed or reason_code not in reasons:
        raise ValueError("recovery request is not in the fixed sensor/reason allowlist")
    if request_dir == WATCHDOG_RECOVERY_REQUEST_DIR and os.geteuid() != 0:
        raise PermissionError("only the privileged Sensor Health service may submit watchdog recovery requests")
    request_dir.mkdir(parents=True, exist_ok=True)
    if request_dir.is_symlink():
        raise OSError("refusing symlinked watchdog recovery request directory")
    try:
        os.chmod(request_dir, 0o700)
    except OSError:
        pass
    payload = {
        "schema_version": "1.0", "request_id": str(uuid4()), "sensor_id": sensor_id,
        "reason_code": reason_code, "requested_by": requested_by, "requested_at": utc_now(),
    }
    path = request_dir / f"{payload['request_id']}.json"
    _atomic_json(path, payload, mode=0o600)
    return path


def _heartbeat_age(db_path: Path, key: str, now_epoch: float) -> float | None:
    if not key or not db_path.is_file():
        return None
    try:
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=1) as connection:
            row = connection.execute("SELECT value FROM background_monitor_state WHERE key=?", (key,)).fetchone()
        if not row or not row[0]:
            return None
        parsed = datetime.fromisoformat(str(row[0]).replace("Z", "+00:00"))
        return max(0.0, now_epoch - parsed.timestamp())
    except (OSError, ValueError, sqlite3.Error):
        return None


class ServiceWatchdog:
    def __init__(
        self,
        *,
        uid: int,
        home: Path,
        specs: Sequence[ServiceSpec] | None = None,
        runner: Callable[..., Any] = subprocess.run,
        integrity_checker: Callable[[ServiceSpec, list[str]], tuple[bool, str]] | None = None,
        state_path: Path = WATCHDOG_STATE_PATH,
        health_path: Path = WATCHDOG_HEALTH_PATH,
        audit_path: Path = WATCHDOG_AUDIT_PATH,
        lock_path: Path = WATCHDOG_LOCK_PATH,
        recovery_request_dir: Path | None = None,
        db_path: Path = Path("/Library/Application Support/MacAuditAgent/mac_audit_agent.sqlite3"),
        now: Callable[[], float] = time.time,
    ) -> None:
        self.uid = int(uid)
        self.home = Path(home)
        self.specs = tuple(specs or known_service_specs(self.uid, self.home))
        self.runner = runner
        self.integrity_checker = integrity_checker or self._default_integrity_check
        self.state_path = Path(state_path)
        self.health_path = Path(health_path)
        self.audit_path = Path(audit_path)
        self.lock_path = Path(lock_path)
        self.recovery_request_dir = Path(recovery_request_dir) if recovery_request_dir is not None else Path(state_path).parent / "recovery-requests"
        self.db_path = Path(db_path)
        self.now = now

    def _run(self, argv: list[str]) -> Any:
        return self.runner(argv, capture_output=True, text=True, timeout=20, check=False)

    def _read_plist(self, spec: ServiceSpec) -> tuple[list[str], str]:
        try:
            info = spec.plist_path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                return [], "plist must be a regular file and not a symlink"
            if info.st_uid != spec.expected_uid:
                return [], f"plist owner mismatch: expected uid {spec.expected_uid}, observed {info.st_uid}"
            if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return [], "plist is group/world writable"
            payload = plistlib.loads(spec.plist_path.read_bytes())
            if payload.get("Label") != spec.label:
                return [], "plist Label does not match the fixed service identity"
            arguments = payload.get("ProgramArguments")
            if not isinstance(arguments, list) or not arguments or not all(isinstance(value, str) and value for value in arguments):
                return [], "plist ProgramArguments is missing or invalid"
            if spec.expected_executable and arguments[0] != spec.expected_executable:
                return [], "plist executable does not match the fixed service path"
            if spec.kind == "system_monitor" and not (
                "mac_audit_agent.monitor" in arguments or "--system-monitor-service" in arguments
            ):
                return [], "system monitor launch role is invalid"
            if spec.kind == "sensor_health" and not (
                "mac_audit_agent.sensor_health_service" in arguments or "--sensor-health" in arguments
            ):
                return [], "sensor health launch role is invalid"
            if spec.kind == "user_notifier" and not (
                "mac_audit_agent.user_notifier" in arguments or "--user-notifier-service" in arguments
            ):
                return [], "user notifier launch role is invalid"
            return list(arguments), ""
        except (OSError, ValueError, plistlib.InvalidFileException) as exc:
            return [], f"plist validation failed: {type(exc).__name__}: {exc}"

    def _default_integrity_check(self, spec: ServiceSpec, arguments: list[str]) -> tuple[bool, str]:
        if spec.kind in {"system_monitor", "sensor_health"}:
            try:
                from mac_audit_agent.launch_agent import (
                    verify_protected_monitor_integrity,
                )

                result = verify_protected_monitor_integrity(scope="system")
                if bool(result.get("tamper_detected")):
                    evidence = result.get("evidence", [])
                    return False, "protected runtime integrity failed: " + "; ".join(str(item) for item in evidence[:3])
                return True, "protected runtime manifest verified"
            except Exception as exc:
                return False, f"protected runtime integrity check failed: {type(exc).__name__}: {exc}"
        if spec.kind == "user_notifier":
            manifest = self.home / "Library" / "Application Support" / "MacAuditAgent" / "runtime" / "install_manifest.json"
            if not manifest.is_file():
                return False, f"trusted notifier runtime manifest is missing: {manifest}"
            return True, "notifier runtime manifest present"
        executable = Path(arguments[0])
        if not executable.is_file() or executable.is_symlink():
            return False, f"service executable is missing or unsafe: {executable}"
        result = self._run([CODESIGN, "--verify", "--strict", "--verbose=4", str(executable)])
        if result.returncode != 0:
            return False, "code signature verification failed: " + _result_text(result)[-1000:]
        detail = self._run([CODESIGN, "-d", "--verbose=4", str(executable)])
        detail_text = _result_text(detail)
        if spec.expected_signing_identifier:
            identifier = next(
                (line.partition("=")[2].strip() for line in detail_text.splitlines() if line.startswith("Identifier=")),
                "",
            )
            if identifier != spec.expected_signing_identifier:
                return False, f"signing identifier mismatch: expected {spec.expected_signing_identifier}, observed {identifier or 'missing'}"
        if spec.required_entitlement:
            entitlements = self._run([CODESIGN, "-d", "--entitlements", "-", "--xml", str(executable)])
            raw = (_result_text(entitlements) or "").encode("utf-8", errors="replace")
            start, end = raw.find(b"<?xml"), raw.find(b"</plist>")
            try:
                entitlement_payload = plistlib.loads(raw[start : end + len(b"</plist>")]) if start >= 0 and end >= start else {}
            except plistlib.InvalidFileException:
                entitlement_payload = {}
            if not bool(entitlement_payload.get(spec.required_entitlement)):
                return False, f"required entitlement is missing: {spec.required_entitlement}"
        return True, "strict code signature verified"

    def observe(self, spec: ServiceSpec, now_epoch: float) -> ServiceObservation:
        if not spec.plist_path.is_file():
            return ServiceObservation(False, False, False, None, None, None, "not installed")
        try:
            result = self._run([LAUNCHCTL, "print", spec.target])
        except Exception as exc:
            return ServiceObservation(True, False, False, None, None, None, f"launchctl failed: {exc}")
        output = _result_text(result)
        loaded = result.returncode == 0
        match = PID_PATTERN.search(output)
        pid = int(match.group(1)) if match else None
        running = loaded and pid is not None and ("state = running" in output.lower() or pid > 0)
        age = _heartbeat_age(spec.heartbeat_database or self.db_path, spec.heartbeat_key, now_epoch)
        fresh = None if age is None else age <= HEARTBEAT_MAX_AGE_SECONDS
        if spec.kind == "sensor_health" and loaded and fresh:
            # Sensor Health is a periodic one-shot. A fresh completed cycle is
            # its liveness proof between launchd invocations.
            running = True
        if fresh is False:
            running = False
        # Health is intentionally user-readable for the GUI.  Do not persist
        # launchctl's environment dump; retain only bounded failure text.
        detail = "" if loaded else output[-500:]
        return ServiceObservation(True, loaded, running, pid, fresh, age, detail)

    def _attempts(self, state: dict[str, Any], label: str, now_epoch: float) -> list[float]:
        raw = state.get("services", {}).get(label, {}).get("repair_attempts", [])
        return [float(item) for item in raw if isinstance(item, (int, float)) and now_epoch - float(item) <= ATTEMPT_WINDOW_SECONDS]

    def _record_audit(self, event: dict[str, Any]) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        if self.audit_path.is_symlink():
            raise RuntimeError(f"refusing symlinked watchdog audit path: {self.audit_path}")
        previous_hash = ""
        try:
            with self.audit_path.open("rb") as handle:
                lines = handle.read().splitlines()
            if lines:
                previous_hash = str(json.loads(lines[-1]).get("record_hash", ""))
        except (OSError, ValueError, TypeError):
            previous_hash = ""
        record = {"schema_version": "1.0", "timestamp": utc_now(), "previous_hash": previous_hash, **event}
        record["record_hash"] = _canonical_hash(record)
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.audit_path, flags, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        os.chmod(self.audit_path, 0o600)

    def _repair(self, spec: ServiceSpec, before: ServiceObservation) -> tuple[list[str], ServiceObservation]:
        actions: list[str] = []
        if not before.loaded:
            bootstrap = self._run([LAUNCHCTL, "bootstrap", spec.domain, str(spec.plist_path)])
            actions.append("bootstrap" if bootstrap.returncode == 0 else f"bootstrap_failed: {_result_text(bootstrap)[-500:]}")
        kickstart = self._run([LAUNCHCTL, "kickstart", "-k", spec.target])
        actions.append("kickstart" if kickstart.returncode == 0 else f"kickstart_failed: {_result_text(kickstart)[-500:]}")
        return actions, self.observe(spec, self.now())

    def run_once(self) -> dict[str, Any]:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        if self.lock_path.is_symlink():
            raise RuntimeError(f"refusing symlinked watchdog lock path: {self.lock_path}")
        lock_flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            lock_flags |= os.O_NOFOLLOW
        lock_handle = os.fdopen(os.open(self.lock_path, lock_flags, 0o600), "a+")
        os.chmod(self.lock_path, 0o600)
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            lock_handle.close()
            return {"status": "already_running", "healthy": True, "timestamp": utc_now(), "services": []}
        now_epoch = self.now()
        state = _load_json(self.state_path)
        state.setdefault("services", {})
        recovery_requests = self._load_recovery_requests()
        reports: list[dict[str, Any]] = []
        try:
            for spec in self.specs:
                if not spec.plist_path.is_file():
                    continue
                before = self.observe(spec, now_epoch)
                requested_recovery = recovery_requests.get(spec.label)
                report: dict[str, Any] = {
                    "label": spec.label,
                    "display_name": spec.display_name,
                    "domain": spec.domain,
                    "plist_path": str(spec.plist_path),
                    "before": asdict(before),
                    "action": "none",
                    "repair_suppressed": False,
                    "integrity_verified": False,
                    "reason": "functional recovery requested" if requested_recovery else "healthy" if before.running else "service is not healthy",
                    "functional_recovery_request": requested_recovery or {},
                }
                arguments, plist_error = self._read_plist(spec)
                if plist_error:
                    report.update(action="blocked", reason=plist_error, after=asdict(before))
                    self._record_audit({"label": spec.label, "action": "repair_blocked", "reason": plist_error})
                    reports.append(report)
                    continue
                integrity_ok, integrity_detail = self.integrity_checker(spec, arguments)
                report["integrity_verified"] = integrity_ok
                if not integrity_ok:
                    report.update(action="blocked", reason=integrity_detail, after=asdict(before))
                    self._record_audit({"label": spec.label, "action": "repair_blocked", "reason": integrity_detail})
                    reports.append(report)
                    continue
                if before.running and not requested_recovery:
                    report.update(reason=integrity_detail, after=asdict(before))
                    reports.append(report)
                    continue
                attempts = self._attempts(state, spec.label, now_epoch)
                service_state = state["services"].setdefault(spec.label, {})
                suppressed_until = float(service_state.get("suppressed_until", 0) or 0)
                if len(attempts) >= MAX_ATTEMPTS_PER_WINDOW and suppressed_until <= now_epoch:
                    suppressed_until = now_epoch + SUPPRESSION_SECONDS
                if suppressed_until > now_epoch:
                    service_state.update(repair_attempts=attempts, suppressed_until=suppressed_until)
                    report.update(
                        action="suppressed",
                        repair_suppressed=True,
                        reason=f"crash-loop protection active until {datetime.fromtimestamp(suppressed_until, timezone.utc).isoformat()}",
                        after=asdict(before),
                    )
                    self._record_audit({"label": spec.label, "action": "repair_suppressed", "reason": report["reason"]})
                    reports.append(report)
                    continue
                attempts.append(now_epoch)
                service_state.update(repair_attempts=attempts, suppressed_until=0)
                actions, after = self._repair(spec, before)
                report.update(action="; ".join(actions), reason=integrity_detail, after=asdict(after))
                self._record_audit(
                    {
                        "label": spec.label,
                        "domain": spec.domain,
                        "action": "repair_attempted",
                        "operations": actions,
                        "before": asdict(before),
                        "after": asdict(after),
                    }
                )
                reports.append(report)
                if requested_recovery:
                    Path(str(requested_recovery.get("request_path", ""))).unlink(missing_ok=True)
            healthy = all(
                bool(item.get("after", {}).get("running"))
                and bool(item.get("integrity_verified"))
                and item.get("action") != "blocked"
                for item in reports
            )
            try:
                from mac_audit_agent.threat_definitions.manager import default_manager

                definition_manager = default_manager()
                definition_health = definition_manager.status()
                active_release = str(definition_health.get("active_version") or "")
                desynchronized = definition_manager.reload_coordinator.desynchronized_sensors(active_release) if active_release else []
                definition_health["desynchronized_sensors"] = desynchronized
                if desynchronized and definition_manager.store.active_bundle_path() is not None:
                    definition_manager.reload_coordinator.validate_and_request(definition_manager.store.active_bundle_path())
                    self._record_audit({
                        "label": "malware_definitions", "action": "safe_reload_requested",
                        "reason": "DEFINITION_SENSOR_DESYNC", "active_release": active_release,
                        "desynchronized_sensors": desynchronized,
                    })
            except Exception as exc:
                definition_health = {
                    "state": "DEGRADED", "error": f"{type(exc).__name__}: {str(exc)[:256]}",
                    "active_definitions_unchanged": True,
                }
            payload = {
                "schema_version": "1.0",
                "timestamp": utc_now(),
                "status": "healthy" if healthy else "degraded",
                "healthy": healthy,
                "persistent_repair_enabled": True,
                "interval_seconds": 60,
                "crash_loop_policy": {
                    "max_attempts": MAX_ATTEMPTS_PER_WINDOW,
                    "window_seconds": ATTEMPT_WINDOW_SECONDS,
                    "suppression_seconds": SUPPRESSION_SECONDS,
                },
                "installed_service_count": len(reports),
                "services": reports,
                "definition_health": definition_health,
                "audit_path": str(self.audit_path),
            }
            state["updated_at"] = payload["timestamp"]
            _atomic_json(self.state_path, state)
            _atomic_json(self.health_path, payload, mode=0o644)
            return payload
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            lock_handle.close()

    def _load_recovery_requests(self) -> dict[str, dict[str, Any]]:
        mapping = {
            "endpoint_security": "com.fuzzlove.MacAuditAgent.EndpointSecuritySensor",
            "ransomware_monitor": "com.fuzzlove.MacAuditAgent.EndpointSecuritySensor",
            "system_monitor": "com.mac-audit-agent.monitor",
            "user_notifier": "com.mac-audit-agent.user-notifier",
            "sensor_health_manager": "com.mac-audit-agent.sensor-health",
        }
        requests: dict[str, dict[str, Any]] = {}
        directory = self.recovery_request_dir
        if not directory.is_dir() or directory.is_symlink():
            return requests
        for path in sorted(directory.glob("*.json"))[:32]:
            try:
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_size > 4096 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    continue
                payload = json.loads(path.read_text(encoding="utf-8"))
                sensor_id = str(payload.get("sensor_id", ""))
                label = mapping.get(sensor_id, "")
                if not label or str(payload.get("reason_code", "")) not in {
                    "PROCESS_NOT_RUNNING", "HEARTBEAT_STALE", "PROCESSING_STALL",
                    "DELIVERY_STALL", "PERSISTENCE_STALL", "EVENT_STREAM_STALE",
                }:
                    continue
                requests[label] = {**payload, "request_path": str(path)}
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
        return requests


def install_watchdog(
    executable: str,
    uid: int,
    *,
    frozen: bool = False,
    runner: Callable[..., Any] = subprocess.run,
    plist_path: Path = WATCHDOG_PLIST_PATH,
    require_root: bool = True,
) -> Path:
    if require_root and os.geteuid() != 0:
        raise PermissionError("Administrator approval is required to install the persistent MSAA Service Watchdog.")
    if runner is subprocess.run:
        from mac_audit_agent.licensing.registration import (
            require_service_registration_license,
        )

        require_service_registration_license(_home_for_uid(uid))
    executable_path = Path(executable)
    if not executable_path.is_file() or not os.access(executable_path, os.X_OK):
        raise FileNotFoundError(f"Watchdog executable is missing or not executable: {executable_path}")
    payload = build_watchdog_plist(str(executable_path), uid, frozen=frozen)
    for directory, mode in ((WATCHDOG_STATE_DIR, 0o700), (WATCHDOG_RUN_DIR, 0o755), (WATCHDOG_LOG_DIR, 0o700), (plist_path.parent, 0o755)):
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, mode)
        except OSError:
            pass
        if os.geteuid() == 0:
            try:
                os.chown(directory, 0, 0)
            except OSError:
                pass
    temporary = plist_path.with_name(f".{plist_path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True))
    os.chmod(temporary, 0o644)
    lint = runner([PLUTIL, "-lint", str(temporary)], capture_output=True, text=True, timeout=20, check=False)
    if lint.returncode != 0:
        temporary.unlink(missing_ok=True)
        raise RuntimeError("Watchdog plist validation failed: " + _result_text(lint))
    if plist_path.exists():
        backup = plist_path.with_suffix(f".plist.backup-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}")
        shutil.copy2(plist_path, backup)
    os.replace(temporary, plist_path)
    os.chmod(plist_path, 0o644)
    if os.geteuid() == 0:
        os.chown(plist_path, 0, 0)
    runner([LAUNCHCTL, "bootout", "system", str(plist_path)], capture_output=True, text=True, timeout=20, check=False)
    bootstrap = runner([LAUNCHCTL, "bootstrap", "system", str(plist_path)], capture_output=True, text=True, timeout=20, check=False)
    if bootstrap.returncode != 0:
        raise RuntimeError("Watchdog bootstrap failed: " + _result_text(bootstrap))
    kickstart = runner([LAUNCHCTL, "kickstart", "-k", f"system/{WATCHDOG_LABEL}"], capture_output=True, text=True, timeout=20, check=False)
    if kickstart.returncode != 0:
        raise RuntimeError("Watchdog start failed: " + _result_text(kickstart))
    return plist_path


def status_payload(health_path: Path = WATCHDOG_HEALTH_PATH) -> dict[str, Any]:
    health = _load_json(health_path)
    installed = WATCHDOG_PLIST_PATH.is_file()
    if not health:
        return {
            "installed": installed,
            "healthy": False,
            "persistent_repair_enabled": installed,
            "status": "installed_waiting_for_health" if installed else "not_installed",
            "health_path": str(health_path),
        }
    try:
        timestamp = datetime.fromisoformat(str(health.get("timestamp", "")).replace("Z", "+00:00"))
        age = max(0.0, (datetime.now(timezone.utc) - timestamp.astimezone(timezone.utc)).total_seconds())
    except (TypeError, ValueError):
        age = None
    fresh = age is not None and age <= HEARTBEAT_MAX_AGE_SECONDS
    payload = {"installed": installed, "health_path": str(health_path), **health, "health_age_seconds": age, "health_fresh": fresh}
    if not fresh:
        payload["healthy"] = False
        payload["status"] = "stale"
    return payload


def _home_for_uid(uid: int) -> Path:
    import pwd

    return Path(pwd.getpwuid(uid).pw_dir)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Persistently verify and repair installed MSAA services.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run-once")
    run_parser.add_argument("--uid", type=int, required=True)
    run_parser.add_argument("--json", action="store_true")
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command == "status":
        payload = status_payload()
    else:
        payload = ServiceWatchdog(uid=args.uid, home=_home_for_uid(args.uid)).run_once()
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"MSAA Service Watchdog: {payload.get('status', 'unknown')}")
    return 0 if bool(payload.get("healthy")) else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ServiceObservation",
    "ServiceSpec",
    "ServiceWatchdog",
    "WATCHDOG_HEALTH_PATH",
    "WATCHDOG_LABEL",
    "WATCHDOG_PLIST_PATH",
    "WATCHDOG_RECOVERY_REQUEST_DIR",
    "build_watchdog_plist",
    "install_watchdog",
    "known_service_specs",
    "request_service_recovery",
    "status_payload",
]
