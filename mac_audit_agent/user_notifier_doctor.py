from __future__ import annotations

import argparse
import json
import os
import plistlib
import pwd
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.launch_agent import LAUNCHCTL_BIN, MAC_AUDIT_AGENT_ENV_DB_PATH, PLUTIL_BIN
from mac_audit_agent.runtime.db_path_resolver import get_active_monitor_db_path
from mac_audit_agent.user_notifier_installer import (
    MAC_AUDIT_AGENT_SETTINGS_PATH,
    USER_NOTIFIER_LABEL,
    UserNotifierInstaller,
)
from mac_audit_agent.runtime.force_mode import ForceArgumentError, ForceMode, log_force_action, parse_force_argument


@dataclass
class UserNotifierDoctorReport:
    healthy: bool
    loaded: bool
    running: bool
    process_pid: int | None
    likely_cause: str = ""
    checks: dict[str, bool] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def diagnose_user_notifier(*, db_path: Path | None = None, home: Path | None = None, runner=None) -> UserNotifierDoctorReport:
    installer = UserNotifierInstaller(db_path=db_path, home=home, runner=runner)
    status = installer.get_user_notifier_status()
    checks: dict[str, bool] = {}
    evidence = status.to_dict()
    recommendations: list[str] = []
    plist_payload: dict[str, Any] = {}
    current_user = pwd.getpwuid(installer.uid)

    checks["plist_exists"] = installer.plist_path.exists()
    if installer.plist_path.exists():
        try:
            plist_payload = plistlib.loads(installer.plist_path.read_bytes())
            checks["plist_valid"] = True
        except Exception as exc:
            checks["plist_valid"] = False
            evidence["plist_error"] = str(exc)
    else:
        checks["plist_valid"] = False

    try:
        st = installer.plist_path.stat()
        checks["owner_is_current_user"] = st.st_uid == installer.uid
        checks["permissions_0644"] = stat.S_IMODE(st.st_mode) == 0o644
        evidence["plist_owner"] = f"{pwd.getpwuid(st.st_uid).pw_name}:{st.st_gid}"
        evidence["plist_mode"] = oct(stat.S_IMODE(st.st_mode))
    except OSError:
        checks["owner_is_current_user"] = False
        checks["permissions_0644"] = False

    env = plist_payload.get("EnvironmentVariables", {}) if isinstance(plist_payload.get("EnvironmentVariables", {}), dict) else {}
    args = plist_payload.get("ProgramArguments", []) if isinstance(plist_payload.get("ProgramArguments", []), list) else []
    checks["launchctl_domain_gui_uid"] = status.launchctl_domain == f"gui/{installer.uid}"
    checks["program_arguments_correct"] = args == [installer.python_executable, "-m", "mac_audit_agent.user_notifier", "--run"] or args == ["/usr/bin/python3", "-m", "mac_audit_agent.user_notifier", "--run"]
    checks["working_directory_exists"] = Path(str(plist_payload.get("WorkingDirectory", ""))).expanduser().exists()
    # Source-mode launch agents intentionally avoid PYTHONPATH and import the
    # staged package from their canonical runtime working directory.  Accept
    # either model, but still require the independent import test below.
    checks["pythonpath_contains_runtime"] = (
        str(installer.runtime_dir) in str(env.get("PYTHONPATH", ""))
        or (status.working_directory == str(installer.runtime_dir) and "-m" in (status.program_arguments or []))
    )
    checks["runtime_package_exists"] = (installer.runtime_package_dir / "user_notifier.py").exists()
    checks["runtime_writable_by_user"] = _owned_writable_dir(installer.runtime_dir, installer.uid)
    checks["app_support_writable_by_user"] = _owned_writable_dir(installer.app_support_dir, installer.uid)
    checks["db_path_environment_exists"] = bool(str(env.get(MAC_AUDIT_AGENT_ENV_DB_PATH, "")).strip())
    checks["settings_path_environment_exists"] = bool(str(env.get(MAC_AUDIT_AGENT_SETTINGS_PATH, "")).strip())
    checks["log_paths_writable"] = _touchable(installer.stdout_path) and _touchable(installer.stderr_path)
    checks["launchctl_print_valid"] = status.loaded
    checks["process_pid_running"] = bool(status.running and status.process_pid) or bool(status.process_pid and _pid_alive(status.process_pid))
    checks["runtime_manifest_exists"] = (installer.runtime_dir / "install_manifest.json").exists()
    checks["import_test_passes"] = _import_test(installer.python_executable, installer.runtime_dir)

    evidence.update(
        {
            "expected_owner": current_user.pw_name,
            "expected_group": "staff or primary group",
            "expected_mode": "0644",
            "app_support_path": str(installer.app_support_dir),
            "runtime_path": str(installer.runtime_dir),
            "environment": {key: env.get(key, "") for key in ["PYTHONPATH", MAC_AUDIT_AGENT_ENV_DB_PATH, MAC_AUDIT_AGENT_SETTINGS_PATH, "PATH"]},
            "last_exit_status": status.last_exit_status,
            "stderr_tail": status.stderr_tail,
            "stdout_tail": status.stdout_tail,
            "launchctl_print_tail": status.launchctl_print[-4000:],
        }
    )

    likely_cause = _classify_likely_cause(checks, evidence)
    if not checks["import_test_passes"]:
        recommendations.append("Repair User Alert Agent to recreate runtime files and PYTHONPATH.")
    if not checks["runtime_manifest_exists"]:
        recommendations.append("Repair User Alert Agent to write canonical runtime install_manifest.json.")
    if not status.running:
        recommendations.append("Bootout, bootstrap, and kickstart com.mac-audit-agent.user-notifier in gui/<uid>.")
    healthy = all(checks.values()) and status.loaded and status.running
    return UserNotifierDoctorReport(
        healthy=healthy,
        loaded=status.loaded,
        running=status.running,
        process_pid=status.process_pid,
        likely_cause=likely_cause,
        checks=checks,
        evidence=evidence,
        recommendations=recommendations,
    )


def repair_user_alert_agent(*, db_path: Path | None = None, home: Path | None = None, runner=None) -> UserNotifierDoctorReport:
    installer = UserNotifierInstaller(db_path=db_path, home=home, runner=runner)
    installer.repair_user_notifier()
    return diagnose_user_notifier(db_path=db_path, home=home, runner=runner)


def _touchable(path: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.touch(exist_ok=True)
        return _owned_writable_file(path, os.getuid())
    except OSError:
        return False


def _owned_writable_dir(path: Path, uid: int) -> bool:
    try:
        st = path.stat()
    except OSError:
        return False
    mode = stat.S_IMODE(st.st_mode)
    return stat.S_ISDIR(st.st_mode) and st.st_uid == uid and bool(mode & stat.S_IWUSR)


def _owned_writable_file(path: Path, uid: int) -> bool:
    try:
        st = path.stat()
    except OSError:
        return False
    mode = stat.S_IMODE(st.st_mode)
    if st.st_uid == uid and mode & stat.S_IWUSR:
        return True
    try:
        return st.st_gid in os.getgroups() and bool(mode & stat.S_IWGRP)
    except OSError:
        return False


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _import_test(python_executable: str, runtime_dir: Path) -> bool:
    try:
        result = subprocess.run(
            [python_executable, "-c", "import mac_audit_agent.user_notifier"],
            cwd=str(runtime_dir),
            env={**os.environ, "PYTHONPATH": str(runtime_dir)},
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def _classify_likely_cause(checks: dict[str, bool], evidence: dict[str, Any]) -> str:
    stderr = str(evidence.get("stderr_tail", "")).lower()
    if evidence.get("source_database_readable") and evidence.get("source_database_integrity") == "ok" and checks.get("process_pid_running"):
        return ""
    if not checks.get("runtime_writable_by_user") or not checks.get("app_support_writable_by_user") or not checks.get("log_paths_writable"):
        return "permission issue"
    if not checks.get("runtime_package_exists") or "modulenotfounderror" in stderr:
        return "import failure"
    if not checks.get("pythonpath_contains_runtime"):
        return "bad PYTHONPATH"
    if not checks.get("working_directory_exists"):
        return "bad working directory"
    if not checks.get("db_path_environment_exists"):
        return "DB open failure"
    if "sqlite" in stderr or "database" in stderr:
        return "DB open failure"
    if "settings" in stderr:
        return "settings parse failure"
    if checks.get("launchctl_print_valid") and not checks.get("process_pid_running"):
        return "crash on startup"
    return "unknown"


def main() -> int:
    raw_argv = sys.argv[1:]
    try:
        cleaned, force_mode = parse_force_argument(raw_argv, command="repair-notifier", supported_scopes={"repair", "diagnostics"}, default_scope="repair" if "--repair" in raw_argv else "diagnostics", require_command=False)
    except ForceArgumentError as exc:
        print(str(exc), file=sys.stderr)
        log_force_action("repair-notifier", ForceMode(enabled=False, scope="unsupported"), result="rejected", error=str(exc))
        return 2
    parser = argparse.ArgumentParser(description="Diagnose, repair, or verify the MSAA User Alert Agent LaunchAgent.")
    parser.add_argument("--repair", action="store_true", help="Rewrite, bootstrap, kickstart, and verify the user alert agent.")
    parser.add_argument("--verify", action="store_true", help="Verify the user alert agent without modifying it.")
    parser.add_argument("--db-path", type=Path, default=None, help="Active MSAA database path the notifier should use.")
    parser.add_argument("--force", "-f", action="store_true", help="Retry safe notifier repair from scratch. Does not delete logs or bypass validation.")
    args = parser.parse_args(cleaned)
    if args.force:
        force_mode.enabled = True
    db_path = args.db_path or get_active_monitor_db_path()
    if force_mode.enabled:
        log_force_action("repair-notifier" if args.repair else "verify-notifier", force_mode, action_taken="retry_notifier_repair" if args.repair else "rerun_notifier_diagnostics", result="started")
        print("Force enabled: cached data will be bypassed and the operation will run fresh.", file=sys.stderr)
    report = repair_user_alert_agent(db_path=db_path) if args.repair else diagnose_user_notifier(db_path=db_path)
    if force_mode.enabled:
        log_force_action("repair-notifier" if args.repair else "verify-notifier", force_mode, action_taken="retry_notifier_repair" if args.repair else "rerun_notifier_diagnostics", result="healthy" if report.healthy else "unhealthy")
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0 if report.healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
