from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from mac_audit_agent.launch_agent import LAUNCHCTL_BIN
from mac_audit_agent.models import utc_now_iso

USER_NOTIFIER_LABEL = "com.mac-audit-agent.user-notifier"


def notifier_wake_marker_path() -> Path:
    return Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "runtime" / "notifier_wake.json"


def notify_user_notifier_event_available(event_id: str, *, db_path: str = "", kickstart: bool = True, runner=None) -> dict[str, Any]:
    runner = runner or subprocess.run
    marker = notifier_wake_marker_path()
    payload = {
        "event_id": event_id,
        "db_path": db_path,
        "created_at": utc_now_iso(),
        "pid": os.getpid(),
        "contains_secrets": False,
    }
    result: dict[str, Any] = {"wake_marker_path": str(marker), "wake_marker_written": False, "kickstart_attempted": False, "kickstart_returncode": None, "kickstart_error": ""}
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        result["wake_marker_written"] = True
    except OSError as exc:
        result["wake_marker_error"] = str(exc)
    if kickstart:
        uid = os.getuid()
        command = [LAUNCHCTL_BIN, "kickstart", "-k", f"gui/{uid}/{USER_NOTIFIER_LABEL}"]
        result["kickstart_attempted"] = True
        try:
            completed = runner(command, capture_output=True, text=True, timeout=5, check=False)
            result["kickstart_returncode"] = getattr(completed, "returncode", None)
            result["kickstart_error"] = (getattr(completed, "stderr", "") or getattr(completed, "stdout", "") or "").strip()
        except Exception as exc:
            result["kickstart_error"] = str(exc)
    return result


__all__ = ["USER_NOTIFIER_LABEL", "notifier_wake_marker_path", "notify_user_notifier_event_available"]
