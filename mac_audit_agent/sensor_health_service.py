"""Periodic launchd entry point for the Sensor Reliability Coordinator."""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import pwd
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

SENSOR_HEALTH_LABEL = "com.mac-audit-agent.sensor-health"
SENSOR_HEALTH_PLIST_PATH = Path("/Library/LaunchDaemons") / f"{SENSOR_HEALTH_LABEL}.plist"
SENSOR_HEALTH_REPORT_PATH = Path("/Library/Application Support/MacAuditAgent/run/sensor-health.json")
SYSTEM_DB_PATH = Path("/Library/Application Support/MacAuditAgent/mac_audit_agent.sqlite3")
LAUNCHCTL = "/bin/launchctl"
PLUTIL = "/usr/bin/plutil"


def build_sensor_health_plist(executable: str, uid: int, *, frozen: bool = False, interval_seconds: int = 60) -> dict[str, Any]:
    arguments = [executable, "--sensor-health", "--uid", str(uid)] if frozen else [
        executable, "-m", "mac_audit_agent.sensor_health_service", "run-once", "--uid", str(uid),
    ]
    return {
        "Label": SENSOR_HEALTH_LABEL,
        "ProgramArguments": arguments,
        "RunAtLoad": True,
        "StartInterval": max(30, int(interval_seconds)),
        "ThrottleInterval": 10,
        "ProcessType": "Background",
        "WorkingDirectory": "/Library/Application Support/MacAuditAgent/runtime",
        "EnvironmentVariables": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", **({} if frozen else {"PYTHONPATH": "/Library/Application Support/MacAuditAgent/runtime"})},
        "StandardOutPath": "/Library/Logs/MacAuditAgent/sensor-health.stdout.log",
        "StandardErrorPath": "/Library/Logs/MacAuditAgent/sensor-health.stderr.log",
    }


def _atomic_report(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def _self_test_due(store, now: float) -> bool:
    next_epoch = float(store.get_manager_state("next_periodic_self_test_epoch", 0) or 0)
    if now < next_epoch:
        return False
    jitter = int.from_bytes(socket.gethostname().encode("utf-8")[:4].ljust(4, b"0"), "big") % 180
    store.set_manager_state("next_periodic_self_test_epoch", now + 900 + jitter)
    return True


def run_once(uid: int, *, database: Path = SYSTEM_DB_PATH, report_path: Path = SENSOR_HEALTH_REPORT_PATH) -> dict[str, Any]:
    from mac_audit_agent.health.manager import default_coordinator

    home = Path(pwd.getpwuid(uid).pw_dir)
    coordinator = default_coordinator(database, system_database=database, user_home=home)
    try:
        report = coordinator.run_cycle(run_self_tests=_self_test_due(coordinator.store, time.time()))
        payload = report.to_dict()
        _atomic_report(report_path, payload)
        with coordinator.store._lock:
            coordinator.store.connection.execute(
                "INSERT OR REPLACE INTO background_monitor_state(key,value) VALUES('sensor_health_manager_last_cycle',?)",
                (datetime.now(timezone.utc).isoformat(),),
            )
            coordinator.store.connection.commit()
        return payload
    finally:
        coordinator.store.close()


def install_sensor_health_service(executable: str, uid: int, *, frozen: bool = False, plist_path: Path = SENSOR_HEALTH_PLIST_PATH) -> Path:
    if sys.platform != "darwin" or os.geteuid() != 0:
        raise PermissionError("Sensor Health service installation requires administrator approval on macOS.")
    from mac_audit_agent.licensing.registration import (
        require_service_registration_license,
    )

    require_service_registration_license(Path(pwd.getpwuid(uid).pw_dir))
    payload = build_sensor_health_plist(executable, uid, frozen=frozen)
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = plist_path.with_name(f".{plist_path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True))
    os.chmod(temporary, 0o644)
    lint = subprocess.run([PLUTIL, "-lint", str(temporary)], capture_output=True, text=True, timeout=20, check=False)
    if lint.returncode != 0:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(f"Sensor Health plist validation failed: {lint.stderr or lint.stdout}")
    if plist_path.exists():
        backup = plist_path.with_suffix(f".plist.backup-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}")
        shutil.copy2(plist_path, backup)
    os.replace(temporary, plist_path)
    os.chmod(plist_path, 0o644)
    os.chown(plist_path, 0, 0)
    subprocess.run([LAUNCHCTL, "bootout", "system", str(plist_path)], capture_output=True, text=True, timeout=20, check=False)
    bootstrap = subprocess.run([LAUNCHCTL, "bootstrap", "system", str(plist_path)], capture_output=True, text=True, timeout=20, check=False)
    if bootstrap.returncode != 0:
        raise RuntimeError(f"Sensor Health bootstrap failed: {bootstrap.stderr or bootstrap.stdout}")
    kickstart = subprocess.run([LAUNCHCTL, "kickstart", "-k", f"system/{SENSOR_HEALTH_LABEL}"], capture_output=True, text=True, timeout=20, check=False)
    if kickstart.returncode != 0:
        raise RuntimeError(f"Sensor Health start failed: {kickstart.stderr or kickstart.stdout}")
    return plist_path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one isolated Sensor Health assurance cycle.")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run-once")
    run.add_argument("--uid", type=int, required=True)
    run.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    payload = run_once(args.uid)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload.get("overall_health") in {"HEALTHY", "HEALTHY_WITH_WARNINGS"} else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["SENSOR_HEALTH_LABEL", "SENSOR_HEALTH_PLIST_PATH", "SENSOR_HEALTH_REPORT_PATH", "build_sensor_health_plist", "install_sensor_health_service", "run_once"]
