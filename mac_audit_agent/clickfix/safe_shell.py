from __future__ import annotations
import os, pty, pwd, secrets, select, signal, sys, termios, fcntl, time, tty
from pathlib import Path
from .shell_config import load_config
from .shell_events import append_event, event_from
from .shell_scanner import scan_request

START=b"\x1b[200~"; END=b"\x1b[201~"
def _real_shell():
    shell=pwd.getpwuid(os.getuid()).pw_shell or "/bin/zsh"
    if Path(shell).name in {"msaa-safe-shell","msaa_clickfix_safe_shell"} or not Path(shell).is_absolute(): raise RuntimeError("unsafe_or_recursive_login_shell")
    return shell
def main():
    if os.environ.get("MSAA_SAFE_SHELL_ACTIVE"): raise SystemExit("MSAA safe shell recursion refused")
    shell=_real_shell(); pid,fd=pty.fork()
    if pid==0: os.environ["MSAA_SAFE_SHELL_ACTIVE"]="1"; os.execv(shell,[shell,"-l"])
    original_terminal = termios.tcgetattr(sys.stdin.fileno()) if os.isatty(sys.stdin.fileno()) else None
    def resize(*_):
        try: fcntl.ioctl(fd,termios.TIOCSWINSZ,fcntl.ioctl(sys.stdin.fileno(),termios.TIOCGWINSZ,b"\0"*8))
        except OSError: pass
    def forward(signum, _frame):
        try: os.killpg(pid, signum)
        except OSError: pass
    signal.signal(signal.SIGWINCH,resize)
    for forwarded in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP): signal.signal(forwarded,forward)
    resize(); paste=bytearray(); collecting=False; held: bytes | None=None; held_event=None; challenge=""; challenge_input=bytearray(); challenge_expires=0.0
    def record_override(event_type):
        if held_event is None: return
        request, result, config = held_event
        if config.local_json_log_enabled:
            try: append_event(event_from(request,result.to_dict(),event_type=event_type,config_source=config.source,coverage="generic_proxy"))
            except OSError: pass
    if original_terminal is not None: tty.setraw(sys.stdin.fileno())
    try:
        while True:
            ready,_,_=select.select([sys.stdin.fileno(),fd],[],[])
            if fd in ready:
                data=os.read(fd,65536)
                if not data: break
                os.write(sys.stdout.fileno(),data)
            if sys.stdin.fileno() in ready:
                data=os.read(sys.stdin.fileno(),65536)
                if not data: break
                if held is not None:
                    if time.monotonic() > challenge_expires:
                        record_override("user_override_expired"); held=None; held_event=None; challenge=""; challenge_input.clear(); os.write(sys.stderr.fileno(),b"\r\nMSAA challenge expired; the held paste was discarded.\r\n")
                    elif START in data or END in data:
                        record_override("user_override_expired"); held=None; held_event=None; challenge=""; challenge_input.clear(); os.write(sys.stderr.fileno(),b"\r\nMSAA rejected a pasted challenge; the held paste was discarded.\r\n"); continue
                    else:
                        challenge_input.extend(data)
                        if len(challenge_input)>128: held=None; challenge=""; challenge_input.clear(); os.write(sys.stderr.fileno(),b"\r\nMSAA challenge input exceeded its limit; the held paste was discarded.\r\n"); continue
                        if b"\r" not in challenge_input and b"\n" not in challenge_input: continue
                        supplied=bytes(challenge_input).splitlines()[0].decode("ascii","ignore")
                        if secrets.compare_digest(supplied,challenge):
                            record_override("user_override_completed"); restored=held.rstrip(b"\r\n"); os.write(fd,START+restored+END); os.write(sys.stderr.fileno(),b"\r\nMSAA restored the held command without a newline. Review it and press Return to execute.\r\n")
                        else: os.write(sys.stderr.fileno(),b"\r\nMSAA challenge did not match; the held paste was discarded.\r\n")
                        held=None; held_event=None; challenge=""; challenge_input.clear(); continue
                try: shell_foreground=os.tcgetpgrp(fd)==pid
                except OSError: shell_foreground=False
                if not shell_foreground: os.write(fd,data); continue
                while data:
                    if not collecting:
                        before,marker,after=data.partition(START)
                        if before: os.write(fd,before)
                        if not marker: break
                        collecting=True; paste.clear(); data=after
                    else:
                        body,marker,after=data.partition(END); paste.extend(body)
                        if len(paste)>128*1024: os.write(sys.stderr.fileno(),b"\nMSAA blocked an oversized paste before execution.\n"); collecting=False; paste.clear(); data=after; continue
                        if not marker: break
                        command=paste.decode("utf-8","replace"); config=load_config(); request={"command":command,"phase":"paste","paste_origin":"generic_proxy","multiline":"\n" in command.rstrip("\n"),"trailing_newline":command.endswith(("\n","\r")),"shell_path":shell,"shell_version":"","terminal_bundle_id":os.environ.get("TERM_PROGRAM",""),"tty":os.ttyname(sys.stdin.fileno()) if os.isatty(sys.stdin.fileno()) else "","session_id":str(pid),"mode":config.mode,"configuration_version":config.configuration_version}
                        result=scan_request(request,config)
                        if result.decision in {"warn","block","error"} and config.local_json_log_enabled:
                            kind="scanner_error" if result.decision=="error" else "paste_"+("blocked" if result.decision=="block" and config.mode=="block" else "warning")
                            try: append_event(event_from(request,result.to_dict(),event_type=kind,config_source=config.source,coverage="generic_proxy"))
                            except OSError: pass
                        if config.mode=="audit" or result.decision=="allow": os.write(fd,START+bytes(paste)+END); data=after
                        elif config.mode=="warn" or result.decision=="warn":
                            held=bytes(paste); held_event=(dict(request),result,config); challenge=secrets.token_hex(4).upper(); challenge_expires=time.monotonic()+60; challenge_input.clear(); record_override("user_override_started"); os.write(sys.stderr.fileno(),f"\r\nMSAA held a suspicious paste. Type {challenge} manually within 60 seconds, then press Return. Input is hidden.\r\n".encode("ascii")); data=b""
                        else: os.write(sys.stderr.fileno(),b"\r\nMSAA blocked a suspicious command before execution. The paste was not forwarded.\r\n"); data=b""
                        collecting=False; paste.clear()
    finally:
        if original_terminal is not None:
            try: termios.tcsetattr(sys.stdin.fileno(),termios.TCSADRAIN,original_terminal)
            except termios.error: pass
        try: os.kill(pid,signal.SIGHUP)
        except OSError: pass
        try: _,status=os.waitpid(pid,0); return os.waitstatus_to_exitcode(status)
        except ChildProcessError: return 1
if __name__=="__main__": raise SystemExit(main())
