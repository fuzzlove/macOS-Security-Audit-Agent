from __future__ import annotations

import argparse
import os
import pwd
import shutil
import sys
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Install or repair MSAA frozen macOS services.")
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--settings-db", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise SystemExit("This installer only supports macOS.")
    if os.geteuid() != 0:
        raise SystemExit("Administrator approval is required. Rerun this command with sudo or the MSAA privileged installer.")
    executable = args.executable.resolve()
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise SystemExit(f"Frozen MSAA executable is missing or not executable: {executable}")
    user = pwd.getpwuid(args.uid)
    os.environ["MSAA_GUI_UID"] = str(args.uid)
    os.environ["MSAA_GUI_HOME"] = user.pw_dir

    from mac_audit_agent.launch_agent import LAUNCHCTL_BIN, SYSTEM_DB_PATH, LaunchAgentManager
    from mac_audit_agent.service_watchdog import install_watchdog
    from mac_audit_agent.sensor_health_service import install_sensor_health_service
    from mac_audit_agent.user_notifier_installer import UserNotifierInstaller

    conflicting = Path(user.pw_dir) / "Library" / "LaunchAgents" / "com.mac-audit-agent.monitor.plist"
    subprocess_result = __import__("subprocess").run(
        [LAUNCHCTL_BIN, "bootout", f"gui/{args.uid}", str(conflicting)],
        capture_output=True,
        text=True,
        check=False,
    )
    if conflicting.exists():
        backup = conflicting.with_suffix(f".plist.disabled-{int(time.time())}")
        shutil.move(conflicting, backup)
        print(f"MON005 repaired: conflicting user monitor disabled at {backup}")
    elif subprocess_result.returncode == 0:
        print("Conflicting user monitor unloaded.")

    manager = LaunchAgentManager(SYSTEM_DB_PATH, scope="system", process_executable=str(executable), frozen=True)
    plist, notes = manager.repair()
    print(f"System LaunchDaemon repaired: {plist}")
    for note in notes:
        print(note)

    notifier = UserNotifierInstaller(
        db_path=SYSTEM_DB_PATH,
        home=Path(user.pw_dir),
        python_executable=str(executable),
        frozen=True,
    )
    notifier.settings_db_path = args.settings_db.expanduser()
    notifier.topology = __import__("mac_audit_agent.runtime.topology", fromlist=["resolve_runtime_topology"]).resolve_runtime_topology(
        notifier.settings_db_path,
        selected_mode="system",
        notifier_event_database=SYSTEM_DB_PATH,
        frozen=True,
        executable=str(executable),
        uid=args.uid,
    )
    notifier.db_path = SYSTEM_DB_PATH
    status = notifier.install_user_notifier()
    print(f"User notifier repaired: loaded={status.loaded} running={status.running} domain={status.launchctl_domain}")
    watchdog_plist = install_watchdog(str(executable), args.uid, frozen=True)
    print(f"Persistent service watchdog installed: {watchdog_plist}")
    sensor_health_plist = install_sensor_health_service(str(executable), args.uid, frozen=True)
    print(f"Sensor Health assurance service installed: {sensor_health_plist}")
    time.sleep(6)
    live = manager.status()
    if not (live.installed and live.loaded and live.running):
        raise SystemExit(f"MON003: daemon verification failed: {live.last_error or live}")
    print(f"System daemon verified: loaded={live.loaded} running={live.running} pid={live.process_pid}")
    watchdog_live = __import__("subprocess").run(
        [LAUNCHCTL_BIN, "print", "system/com.mac-audit-agent.service-watchdog"],
        capture_output=True,
        text=True,
        check=False,
    )
    if watchdog_live.returncode != 0:
        raise SystemExit(f"Persistent service watchdog verification failed: {watchdog_live.stderr or watchdog_live.stdout}")
    print("Persistent service repair verified: launchd registration is active (60-second interval).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
