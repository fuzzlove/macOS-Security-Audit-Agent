from __future__ import annotations

import argparse, json, os, sys
from dataclasses import replace
from .shell_config import load_config
from .shell_events import ADAPTER_EVENT_TYPES, append_event, event_from
from .shell_scanner import scan_request

def _adapter_event(event_type: str, config) -> int:
    if event_type not in ADAPTER_EVENT_TYPES:
        return 2
    request={"phase":"test","mode":config.mode,"paste_origin":"none","shell_path":os.environ.get("MSAA_CLICKFIX_SHELL_PATH",""),"shell_version":os.environ.get("MSAA_CLICKFIX_SHELL_VERSION",""),"terminal_bundle_id":os.environ.get("TERM_PROGRAM",""),"tty":os.environ.get("TTY",""),"session_id":os.environ.get("MSAA_CLICKFIX_SESSION_ID",str(os.getppid()))}
    decision={"decision":"error" if event_type in {"adapter_integrity_failure","scanner_error","scanner_timeout"} else "allow","score":0,"confidence":"high","rule_ids":[],"command_sha256":"","command_length":0,"normalized_length":0,"decoder_depth":0,"scanner_version":"1.0.0","configuration_version":config.configuration_version,"processing_time_ms":0,"error":event_type if event_type.endswith(("failure","timeout")) else ""}
    if config.local_json_log_enabled:
        append_event(event_from(request,decision,event_type=event_type,config_source=config.source,coverage="shell_pre_submission"))
    return 0

def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(add_help=False);parser.add_argument("--event",choices=sorted(ADAPTER_EVENT_TYPES));args=parser.parse_args(argv)
    config=load_config()
    if args.event:
        try:return _adapter_event(args.event,config)
        except OSError:return 2
    raw=sys.stdin.buffer.read(128*1024+1)
    if len(raw)>config.maximum_command_bytes: command=""; forced="error"
    else: command=raw.decode("utf-8","replace"); forced=""
    request={"schema":"msaa.clickfix.request.v1","command":command,"phase":os.environ.get("MSAA_CLICKFIX_PHASE","accept_line"),"paste_origin":os.environ.get("MSAA_CLICKFIX_PASTE_ORIGIN","none"),"multiline":"\n" in command.rstrip("\n"),"trailing_newline":command.endswith(("\n","\r")),"shell_path":os.environ.get("MSAA_CLICKFIX_SHELL_PATH",""),"shell_version":os.environ.get("MSAA_CLICKFIX_SHELL_VERSION",""),"terminal_bundle_id":os.environ.get("TERM_PROGRAM",""),"tty":os.environ.get("TTY",""),"session_id":os.environ.get("MSAA_CLICKFIX_SESSION_ID",str(os.getppid())),"mode":config.mode,"configuration_version":config.configuration_version}
    risk=scan_request(request,config)
    if forced: risk=replace(risk,decision="error",error="command_size_limit")
    result=risk
    if config.mode=="audit" and risk.decision in {"warn","block"}: result=replace(risk,decision="allow")
    elif config.mode=="warn" and risk.decision=="block": result=replace(risk,decision="warn")
    if risk.decision in {"warn","block","error"} and config.local_json_log_enabled:
        event_type="scanner_error" if risk.decision=="error" else ("paste_" if request["phase"]=="paste" else "submission_")+("blocked" if result.decision=="block" else "warning")
        try: append_event(event_from(request,result.to_dict(),event_type=event_type,config_source=config.source,coverage="shell_pre_submission"))
        except OSError: pass
    result=result.to_dict()
    sys.stdout.write(json.dumps(result,separators=(",",":"),sort_keys=True)+"\n"); return 0
if __name__=="__main__": raise SystemExit(main())
