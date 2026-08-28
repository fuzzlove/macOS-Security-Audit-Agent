from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .models import SecurityControlState
from .redaction import redact_text
from .registry import SecurityControlDefinition

SAFE_ENV = {"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","LANG":"C","LC_ALL":"C"}
ALLOWED_EXECUTABLES = frozenset({"/usr/bin/csrutil","/usr/sbin/spctl","/usr/bin/fdesetup","/usr/libexec/ApplicationFirewall/socketfilterfw","/sbin/pfctl","/usr/bin/defaults","/bin/launchctl","/usr/sbin/systemsetup","/usr/bin/profiles"})


@dataclass(frozen=True)
class CommandSpec:
    argv: tuple[str, ...]
    timeout_seconds: float = 5.0
    max_output_bytes: int = 262_144


def run_trusted_command(spec: CommandSpec, runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run) -> tuple[str,str]:
    if not spec.argv or spec.argv[0] not in ALLOWED_EXECUTABLES: raise ValueError("SECURITY_CONTROL_EXECUTABLE_NOT_ALLOWLISTED")
    result=runner(list(spec.argv),capture_output=True,text=True,timeout=spec.timeout_seconds,env=dict(SAFE_ENV),shell=False,check=False)
    output=(result.stdout or "")[:spec.max_output_bytes]
    if len((result.stdout or "").encode("utf-8",errors="replace")) > spec.max_output_bytes: return "", "COLLECTION_OUTPUT_LIMIT"
    return redact_text(output), "" if result.returncode == 0 else f"COLLECTION_EXIT_{result.returncode}"


def collect_command_state(definition:SecurityControlDefinition,spec:CommandSpec,parser:Callable[[str],dict[str,object]],runner:Callable[...,subprocess.CompletedProcess[str]]=subprocess.run)->SecurityControlState:
    now=datetime.now(timezone.utc)
    try:
        output,error=run_trusted_command(spec,runner)
        value=parser(output) if not error else {}
        digest=hashlib.sha256(output.encode("utf-8")).hexdigest() if output else None
        return SecurityControlState(definition.control_id,definition.category,now,value,"trusted_command",0.9 if not error else 0.2,"success" if not error else "error",error or None,digest)
    except subprocess.TimeoutExpired:
        return SecurityControlState(definition.control_id,definition.category,now,{},"trusted_command",0.0,"error","COLLECTION_TIMEOUT",None)
    except (OSError,ValueError) as exc:
        return SecurityControlState(definition.control_id,definition.category,now,{},"trusted_command",0.0,"error",type(exc).__name__.upper(),None)


def collect_file_metadata(definition:SecurityControlDefinition,path:Path)->SecurityControlState:
    now=datetime.now(timezone.utc)
    try:
        stat=path.lstat(); value={"exists":True,"mode":oct(stat.st_mode & 0o7777),"uid":stat.st_uid,"gid":stat.st_gid,"size":stat.st_size,"mtime_ns":stat.st_mtime_ns,"is_symlink":path.is_symlink()}
        digest=hashlib.sha256(str(sorted(value.items())).encode()).hexdigest()
        return SecurityControlState(definition.control_id,definition.category,now,value,"file_metadata",0.75,"success",None,digest)
    except FileNotFoundError:
        return SecurityControlState(definition.control_id,definition.category,now,{"exists":False},"file_metadata",0.75,"success",None,None)
    except PermissionError:
        return SecurityControlState(definition.control_id,definition.category,now,{},"file_metadata",0.2,"reduced_visibility","COLLECTION_PERMISSION_DENIED",None)
