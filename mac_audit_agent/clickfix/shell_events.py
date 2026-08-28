from __future__ import annotations

import fcntl
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

USER_LOG = Path.home() / "Library/Logs/MSAA/clickfix-events.jsonl"
ALLOWED = {"schema","event_id","timestamp","event_type","phase","decision","mode","score","confidence","rule_ids","paste_origin","multiline","trailing_newline","command_sha256","command_length","normalized_length","decoder_depth","shell_path","shell_version","terminal_bundle_id","tty","session_id","scanner_version","adapter_version","configuration_version","configuration_source","coverage_level","processing_time_ms","error_code"}
ADAPTER_EVENT_TYPES = frozenset({"adapter_loaded","adapter_integrity_failure","user_override_started","user_override_completed","user_override_expired","scanner_error","scanner_timeout","coverage_degraded","unsupported_shell","configuration_error"})


def event_from(request: dict[str, Any], decision: dict[str, Any], *, event_type: str, config_source: str, coverage: str, adapter_version: str = "1.0.0") -> dict[str, Any]:
    tty = str(request.get("tty") or "")
    payload = {"schema":"msaa.clickfix.event.v1","event_id":str(uuid4()),"timestamp":datetime.now(timezone.utc).isoformat(),"event_type":event_type,"phase":request.get("phase","test"),"mode":request.get("mode","audit"),"paste_origin":request.get("paste_origin","unknown"),"multiline":bool(request.get("multiline")),"trailing_newline":bool(request.get("trailing_newline")),"shell_path":str(request.get("shell_path") or "")[:512],"shell_version":str(request.get("shell_version") or "")[:128],"terminal_bundle_id":str(request.get("terminal_bundle_id") or "")[:256],"tty":Path(tty).name[:128],"session_id":str(request.get("session_id") or "")[:128],"adapter_version":adapter_version,"configuration_source":config_source,"coverage_level":coverage,"error_code":decision.get("error") or ""}
    for key in ("decision","score","confidence","rule_ids","command_sha256","command_length","normalized_length","decoder_depth","scanner_version","configuration_version","processing_time_ms"): payload[key]=decision.get(key)
    return {key: payload[key] for key in ALLOWED if key in payload}


def append_event(event: dict[str, Any], path: Path = USER_LOG) -> None:
    safe = {key: value for key,value in event.items() if key in ALLOWED}
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700); os.chmod(path.parent,0o700)
    fd = os.open(path, os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX); os.write(fd,(json.dumps(safe,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode("ascii")); os.fsync(fd)
    finally: os.close(fd)
