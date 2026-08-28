from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from typing import Any

from mac_audit_agent.runtime.python_compat import current_python_gui_compatibility


@dataclass(frozen=True)
class PlatformProfile:
    architecture: str
    translated_rosetta: bool
    macos_version: str
    macos_build: str
    cpu_count: int
    memory_mb: int
    battery_state: str
    low_power_mode: str
    homebrew_prefixes: list[str]
    supported_python_gui_runtime: bool
    python_version: str
    qt_runtime_reason: str
    optional_tools: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _run_text(args: list[str], timeout: int = 3) -> str:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False).stdout.strip()
    except Exception:
        return ""


def detect_platform_profile() -> PlatformProfile:
    arch = platform.machine() or _run_text(["/usr/bin/arch"]) or "unknown"
    translated = _run_text(["/usr/sbin/sysctl", "-n", "sysctl.proc_translated"]) == "1"
    memory_bytes = int(_run_text(["/usr/sbin/sysctl", "-n", "hw.memsize"]) or "0")
    compat = current_python_gui_compatibility()
    tools = {name: (shutil.which(name) or "") for name in ["nmap", "lsof", "netstat", "kmutil", "systemextensionsctl", "csrutil", "spctl", "fdesetup", "softwareupdate", "launchctl", "codesign"]}
    return PlatformProfile(
        architecture="translated_rosetta" if translated else arch,
        translated_rosetta=translated,
        macos_version=_run_text(["/usr/bin/sw_vers", "-productVersion"]),
        macos_build=_run_text(["/usr/bin/sw_vers", "-buildVersion"]),
        cpu_count=os.cpu_count() or 1,
        memory_mb=memory_bytes // (1024 * 1024) if memory_bytes else 0,
        battery_state=_run_text(["/usr/bin/pmset", "-g", "batt"], timeout=2),
        low_power_mode=_run_text(["/usr/bin/pmset", "-g", "custom"], timeout=2),
        homebrew_prefixes=[prefix for prefix in ["/opt/homebrew", "/usr/local"] if os.path.isdir(prefix)],
        supported_python_gui_runtime=compat.supported_for_gui,
        python_version=compat.version,
        qt_runtime_reason=compat.reason,
        optional_tools=tools,
    )
