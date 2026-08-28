from __future__ import annotations

import json
import sys

from .shell_config import ShellGuardConfig, load_config
from .shell_events import append_event, event_from
from .shell_scanner import scan_request

MAX_REQUEST = 256 * 1024


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(raw) > MAX_REQUEST: raise ValueError("request_size_limit")
        request = json.loads(raw.decode("utf-8"))
        if not isinstance(request, dict) or request.get("schema") != "msaa.clickfix.request.v1": raise ValueError("invalid_schema")
        if request.get("phase") not in {"paste","accept_line","exec_observation","test"}: raise ValueError("invalid_phase")
        config = load_config(); result = scan_request(request, config); payload = result.to_dict()
        if config.local_json_log_enabled and (payload["decision"] in {"warn","block","error"}):
            kind = "scanner_error" if payload["decision"] == "error" else ("paste_" if request.get("phase")=="paste" else "submission_") + ("blocked" if payload["decision"]=="block" else "warning")
            try:
                append_event(event_from(request,payload,event_type=kind,config_source=config.source,coverage="shell_pre_submission"))
            except OSError:
                # Detection remains authoritative when optional local logging is
                # unavailable. Adapters must not execute a paste because a log
                # directory is unwritable.
                pass
    except Exception as exc:
        config=ShellGuardConfig(); request={"phase":"test","mode":"audit"}; payload=scan_request({"command":"","phase":"test"},config).to_dict(); payload.update({"decision":"error","error":f"request_error:{type(exc).__name__}"})
    sys.stdout.write(json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n")
    return 0 if payload["decision"] != "error" else 2


if __name__ == "__main__": raise SystemExit(main())
