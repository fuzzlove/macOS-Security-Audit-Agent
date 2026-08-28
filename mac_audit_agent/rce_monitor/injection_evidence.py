from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any, Callable

from mac_audit_agent.secure_evidence_collection import EvidenceRepository

from .redaction import redact_text


COMMANDS = {
    "process": (Path("/bin/ps"), 4, 512_000),
    "codesign": (Path("/usr/bin/codesign"), 8, 512_000),
    "vmmap": (Path("/usr/bin/vmmap"), 15, 4_000_000),
    "lsof": (Path("/usr/sbin/lsof"), 10, 2_000_000),
    "sample": (Path("/usr/bin/sample"), 8, 2_000_000),
}


class InjectionEvidenceCollector:
    """Explicit analyst-invoked, read-only macOS injection snapshot collector."""
    def __init__(self, repository: EvidenceRepository, runner: Callable[...,Any] | None=None) -> None:
        self.repository=repository; self.runner=runner or subprocess.run

    @staticmethod
    def _pid(value:Any)->int:
        pid=int(value)
        if pid<=0 or pid>2_147_483_647: raise ValueError("invalid process identifier")
        return pid

    def capture(self,case_id:str,analyst:str,*,source_process:dict[str,Any],target_process:dict[str,Any])->dict[str,Any]:
        source_pid=self._pid(source_process.get("pid")); target_pid=self._pid(target_process.get("pid"))
        target_path=Path(str(target_process.get("executable", "")))
        if not target_path.is_absolute(): raise ValueError("target executable path must be absolute")
        commands={
          "process_source":("process",["-p",str(source_pid),"-o","pid=,ppid=,user=,lstart=,comm=,args="]),
          "process_target":("process",["-p",str(target_pid),"-o","pid=,ppid=,user=,lstart=,comm=,args="]),
          "target_codesign":("codesign",["-dvvv","--entitlements",":-",str(target_path)]),
          "target_vmmap":("vmmap",["-interleaved",str(target_pid)]),
          "target_lsof":("lsof",["-nP","-p",str(target_pid)]),
          "target_sample":("sample",[str(target_pid),"1","1"]),
        }
        collectors={name:(lambda kind=kind,args=args:self._run(kind,args)) for name,(kind,args) in commands.items()}
        collectors["injection_identity"] = lambda:{"source":self._identity(source_process),"target":self._identity(target_process),"pcap_status":"NOT_COLLECTED_REQUIRES_SEPARATE_EXPLICIT_APPROVAL"}
        return self.repository.collect_snapshot(case_id,analyst,collectors)

    def _run(self,kind:str,args:list[str])->dict[str,Any]:
        executable,timeout,limit=COMMANDS[kind]
        if not executable.is_file(): raise RuntimeError(f"fixed collector unavailable: {kind}")
        completed=self.runner([str(executable),*args],capture_output=True,text=True,timeout=timeout,check=False,env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin","LC_ALL":"C"})
        combined=((completed.stdout or "")+("\n" if completed.stdout and completed.stderr else "")+(completed.stderr or ""))
        encoded=combined.encode("utf-8",errors="replace"); truncated=len(encoded)>limit
        safe=redact_text(encoded[:limit].decode("utf-8",errors="replace"),limit=limit)
        return {"collector":kind,"executable":str(executable),"arguments":args,"returncode":int(completed.returncode),"timed_out":False,"output":safe,"output_sha256":hashlib.sha256(safe.encode()).hexdigest(),"truncated":truncated}

    @staticmethod
    def _identity(process:dict[str,Any])->dict[str,Any]:
        return {key:process.get(key) for key in ("pid","ppid","executable","sha256","signing_status","team_id","cdhash") if process.get(key) not in {None,""}}


__all__=["InjectionEvidenceCollector"]
