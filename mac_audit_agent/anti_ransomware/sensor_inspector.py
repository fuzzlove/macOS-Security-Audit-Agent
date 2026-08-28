from __future__ import annotations

import grp
import hashlib
import json
import plistlib
import pwd
import re
import sqlite3
import stat
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .health import (
    EXPECTED_HELPER_PATH,
    EXPECTED_SENSOR_PATH,
    ESClientResult,
    RuntimeEvidence,
)

HEALTH_PATH = Path("/Library/Application Support/MacAuditAgent/run/endpoint-security-health.json")
SENSOR_LABEL = "com.fuzzlove.MacAuditAgent.EndpointSecuritySensor"
HELPER_LABEL = "com.fuzzlove.MacAuditAgent.ContainmentHelper"
MAX_HEALTH_AGE_SECONDS = 30.0
MAX_SYSTEM_HEARTBEAT_AGE_SECONDS = 30.0
SYSTEM_MONITOR_DB = Path("/Library/Application Support/MacAuditAgent/mac_audit_agent.sqlite3")


def _development_observer_status(path: Path = SYSTEM_MONITOR_DB, *, now: datetime | None = None) -> dict:
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=1)
        rows = connection.execute(
            "SELECT key,value FROM background_monitor_state WHERE key IN ("
            "'anti_ransomware_prototype_status','anti_ransomware_prototype_roots',"
            "'anti_ransomware_prototype_last_event','anti_ransomware_prototype_window_count',"
            "'anti_ransomware_prototype_events_observed_total','anti_ransomware_prototype_events_dropped_total',"
            "'anti_ransomware_prototype_fixture_receipts','anti_ransomware_prototype_last_fixture_challenge',"
            "'anti_ransomware_prototype_last_fixture_event','last_heartbeat',"
            "'anti_ransomware_prototype_limitations','clickfix_daemon_bridge_status',"
            "'anti_ransomware_yara_backend_state','anti_ransomware_yara_active',"
            "'anti_ransomware_yara_rule_count','anti_ransomware_hash_active',"
            "'anti_ransomware_hash_indicator_count','anti_ransomware_definition_version')"
        ).fetchall()
        connection.close()
        values = {str(key): str(value) for key, value in rows}
        try: roots = json.loads(values.get("anti_ransomware_prototype_roots", "[]"))
        except json.JSONDecodeError: roots = []
        try: receipts = json.loads(values.get("anti_ransomware_prototype_fixture_receipts", "[]"))
        except json.JSONDecodeError: receipts = []
        if not isinstance(receipts, list):
            receipts = []
        heartbeat = str(values.get("last_heartbeat", ""))
        try:
            parsed_heartbeat = datetime.fromisoformat(heartbeat.replace("Z", "+00:00"))
            parsed_heartbeat = parsed_heartbeat.replace(tzinfo=timezone.utc) if parsed_heartbeat.tzinfo is None else parsed_heartbeat.astimezone(timezone.utc)
            heartbeat_age = max(0.0, ((now or datetime.now(timezone.utc)) - parsed_heartbeat).total_seconds())
        except (TypeError, ValueError):
            heartbeat_age = None
        heartbeat_fresh = heartbeat_age is not None and heartbeat_age <= MAX_SYSTEM_HEARTBEAT_AGE_SECONDS
        configured_running = values.get("anti_ransomware_prototype_status") == "running"
        return {
            "running": configured_running and heartbeat_fresh,
            "configured_state": values.get("anti_ransomware_prototype_status", "unavailable"),
            "system_heartbeat": heartbeat,
            "system_heartbeat_age_seconds": heartbeat_age,
            "system_heartbeat_fresh": heartbeat_fresh,
            "mode": "DEVELOPMENT_OBSERVATION_ONLY",
            "roots": roots,
            "last_event": values.get("anti_ransomware_prototype_last_event", ""),
            "recent_window_count": int(values.get("anti_ransomware_prototype_window_count", "0") or 0),
            "events_observed_total": int(values.get("anti_ransomware_prototype_events_observed_total", "0") or 0),
            "events_dropped_total": int(values.get("anti_ransomware_prototype_events_dropped_total", "0") or 0),
            "fixture_receipts": [item for item in receipts[-128:] if isinstance(item, dict)],
            "last_fixture_challenge": values.get("anti_ransomware_prototype_last_fixture_challenge", ""),
            "last_fixture_event": values.get("anti_ransomware_prototype_last_fixture_event", ""),
            "limitations": values.get("anti_ransomware_prototype_limitations", ""),
            "clickfix_daemon_bridge_status": values.get("clickfix_daemon_bridge_status", "unavailable"),
            "yara_backend_state": values.get("anti_ransomware_yara_backend_state", "unavailable"),
            "yara_active": values.get("anti_ransomware_yara_active") == "1",
            "yara_rule_count": int(values.get("anti_ransomware_yara_rule_count", "0") or 0),
            "hash_active": values.get("anti_ransomware_hash_active") == "1",
            "hash_indicator_count": int(values.get("anti_ransomware_hash_indicator_count", "0") or 0),
            "definition_version": values.get("anti_ransomware_definition_version", ""),
        }
    except (OSError, ValueError, sqlite3.Error):
        return {"running": False, "mode": "DEVELOPMENT_OBSERVATION_ONLY", "roots": [], "clickfix_daemon_bridge_status": "unavailable"}


def _run(argv: list[str], timeout: int = 5):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None


def _field(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}=(.*)$", text, re.MULTILINE)
    return match.group(1).strip() if match else ""


def _codesign(path: Path, runner: Callable):
    verify = runner(["/usr/bin/codesign", "--verify", "--strict", "--verbose=4", str(path)])
    detail = runner(["/usr/bin/codesign", "-d", "--verbose=4", "--requirements", "-", str(path)])
    ent = runner(["/usr/bin/codesign", "-d", "--entitlements", "-", "--xml", str(path)])
    text = detail.stderr if detail else ""
    embedded = False
    if ent:
        for stream in (ent.stdout, ent.stderr):
            raw = stream.encode()
            start = raw.find(b"<?xml")
            end = raw.find(b"</plist>", start)
            if start >= 0 and end >= 0:
                try:
                    embedded = bool(plistlib.loads(raw[start : end + len(b"</plist>")]).get("com.apple.developer.endpoint-security.client"))
                    break
                except Exception:
                    pass
    flags = _field(text, "CodeDirectory")
    return {
        "signature_valid": bool(verify and verify.returncode == 0),
        "team_id": _field(text, "TeamIdentifier"),
        "signing_identifier": _field(text, "Identifier"),
        "cdhash": _field(text, "CDHash"),
        "designated_requirement": next((line.removeprefix("designated => ").strip() for line in text.splitlines() if line.startswith("designated => ")), ""),
        "hardened_runtime": "runtime" in flags.lower() or "runtime" in text.lower(),
        "entitlement_embedded": embedded,
    }


def _boot_session(runner: Callable) -> str:
    result = runner(["/usr/sbin/sysctl", "-n", "kern.boottime"])
    raw = result.stdout if result and result.returncode == 0 else ""
    match = re.search(r"sec\s*=\s*(\d+)\s*,\s*usec\s*=\s*(\d+)", raw)
    return f"{match.group(1)}:{match.group(2)}" if match else "unknown"


def _trusted_health(path: Path, *, owner_uid: int, now: float, build_id: str, boot_id: str):
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return {}, "untrusted_permissions"
        payload = json.loads(path.read_text(encoding="utf-8"))
        required = {"build_id", "boot_session_id", "recorded_at", "client_result"}
        if not required.issubset(payload) or payload["build_id"] != build_id:
            return {}, "identity_mismatch"
        if boot_id != "unknown" and payload["boot_session_id"] != boot_id:
            return {}, "identity_mismatch"
        if not isinstance(payload["boot_session_id"], str) or not payload["boot_session_id"]:
            return {}, "identity_mismatch"
        if now - float(payload["recorded_at"]) > MAX_HEALTH_AGE_SECONDS or float(payload["recorded_at"]) > now + 5:
            return {}, "stale"
        return payload, "accepted"
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}, "unavailable"


def _protected_runtime_integrity() -> bool:
    """Verify the installed signed/hash-bound runtime independently of containment readiness."""
    try:
        from mac_audit_agent.launch_agent import verify_protected_monitor_integrity

        result = verify_protected_monitor_integrity(scope="system")
        return result.get("overall_status") == "verified" and not bool(result.get("tamper_detected"))
    except (OSError, RuntimeError, ValueError, TypeError):
        return False


def inspect_runtime_environment(
    *, current_build_id: str = "source", sensor_path: Path = EXPECTED_SENSOR_PATH,
    helper_path: Path = EXPECTED_HELPER_PATH, health_path: Path = HEALTH_PATH,
    runner: Callable = _run, required_owner_uid: int = 0, now: float | None = None,
) -> RuntimeEvidence:
    now = time.time() if now is None else now
    boot_id = _boot_session(runner)
    details = {"expected_path": str(sensor_path), "health_path": str(health_path)}
    details["development_observer"] = _development_observer_status()
    try:
        info = sensor_path.lstat()
        artifact = stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)
    except OSError:
        info = None
        artifact = False
    installed = artifact and sensor_path == EXPECTED_SENSOR_PATH
    signature = {"signature_valid": False, "team_id": "", "signing_identifier": "", "cdhash": "", "designated_requirement": "", "hardened_runtime": False, "entitlement_embedded": False}
    architecture = ""
    if artifact:
        signature = _codesign(sensor_path, runner)
        file_result = runner(["/usr/bin/file", str(sensor_path)])
        architecture = file_result.stdout.strip() if file_result and file_result.returncode == 0 else ""
        details.update({"owner_uid": info.st_uid, "owner": pwd.getpwuid(info.st_uid).pw_name, "group_gid": info.st_gid,
                        "group": grp.getgrgid(info.st_gid).gr_name, "mode": oct(stat.S_IMODE(info.st_mode)),
                        "permissions_valid": info.st_uid == required_owner_uid and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH),
                        "sha256": hashlib.sha256(sensor_path.read_bytes()).hexdigest()})
    details.update(signature)
    gatekeeper = runner(["/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", str(sensor_path)]) if artifact else None
    details["gatekeeper_accepted"] = bool(gatekeeper and gatekeeper.returncode == 0)
    details["architecture"] = architecture

    launch = runner(["/bin/launchctl", "print", f"system/{SENSOR_LABEL}"])
    loaded = bool(installed and launch and launch.returncode == 0)
    running = bool(loaded and re.search(r"\bstate = running\b", launch.stdout))
    helper_installed = helper_path.is_file() and helper_path == EXPECTED_HELPER_PATH
    helper_launch = runner(["/bin/launchctl", "print", f"system/{HELPER_LABEL}"])
    helper_running = bool(helper_installed and helper_launch and helper_launch.returncode == 0 and re.search(r"\bstate = running\b", helper_launch.stdout))

    live, health_state = _trusted_health(health_path, owner_uid=required_owner_uid, now=now, build_id=current_build_id, boot_id=boot_id)
    details["live_health_evidence"] = health_state
    details["boot_session_verification"] = "kernel_verified" if boot_id != "unknown" else "fresh_root_owned_health_fallback"
    effective_boot_id = boot_id if boot_id != "unknown" else str(live.get("boot_session_id", ""))
    try:
        client_result = ESClientResult(live.get("client_result", ESClientResult.SENSOR_NOT_INSTALLED if not installed else ESClientResult.SENSOR_NOT_RUNNING if not running else ESClientResult.CONNECTION_NOT_ATTEMPTED))
    except ValueError:
        client_result = ESClientResult.INTERNAL_ERROR
    connected = client_result is ESClientResult.SUCCESS and bool(live.get("connected"))
    return RuntimeEvidence(
        build_id=current_build_id if live else "", current_build_id=current_build_id,
        boot_session_id=effective_boot_id if live else "", current_boot_session_id=effective_boot_id, fresh=bool(live),
        sensor_artifact_exists=artifact, sensor_installed=installed, sensor_loaded=loaded, sensor_running=running,
        sensor_signature_valid=signature["signature_valid"], sensor_team_id=signature["team_id"],
        sensor_signing_identifier=signature["signing_identifier"], sensor_cdhash=signature["cdhash"], sensor_architecture=architecture,
        sensor_version=str(live.get("sensor_version", "")), sensor_heartbeat_fresh=bool(live),
        entitlement_embedded=signature["entitlement_embedded"], entitlement_accepted=bool(live.get("entitlement_accepted")),
        tcc_approval_present=bool(live.get("privacy_approval_present")), privacy_approval_source=str(live.get("privacy_approval_source", "none")),
        endpoint_security_client_result=client_result, endpoint_security_connected=connected,
        endpoint_security_subscriptions_active=connected and bool(live.get("subscriptions_active")),
        endpoint_security_live_event_seen=connected and bool(live.get("live_event_seen")),
        endpoint_security_sequence_gap_detected=bool(live.get("sequence_gap_detected")),
        sequence_tracking_active=connected and bool(live.get("sequence_tracking_active")),
        containment_helper_installed=helper_installed, containment_helper_running=helper_running,
        system_engine_running=bool(details["development_observer"].get("system_heartbeat_fresh")),
        system_engine_heartbeat_fresh=bool(details["development_observer"].get("system_heartbeat_fresh")),
        self_integrity_valid=_protected_runtime_integrity(),
        policy_signature_valid=False, rule_package_signature_valid=False,
        sensor_details=details,
    )
