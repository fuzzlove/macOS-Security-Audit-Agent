from __future__ import annotations

import os
from pathlib import Path

PROTECTED_NAMES = {"kernel_task", "launchd", "WindowServer", "loginwindow", "securityd", "opendirectoryd", "tccd"}
PROTECTED_PREFIXES = (Path("/System"), Path("/usr"), Path("/bin"), Path("/sbin"), Path("/private/var/db"))


def protected_path(path: Path) -> tuple[bool, str]:
    try: resolved = path.resolve(strict=False)
    except OSError: return True, "Path cannot be safely canonicalized."
    if path.is_symlink(): return True, "Symlink targets are never removal candidates."
    if any(resolved == prefix or prefix in resolved.parents for prefix in PROTECTED_PREFIXES): return True, "Protected macOS system location."
    if "MacAuditAgent" in resolved.parts or "macOS-Security-Audit-Agent" in resolved.parts: return True, "Active MSAA component or project asset."
    return False, ""


def protected_process(pid: int, name: str, executable: Path) -> tuple[bool, str]:
    if pid in {0, 1, os.getpid()}: return True, "Kernel, launchd, or the current MSAA process."
    if name in PROTECTED_NAMES: return True, "Critical macOS process policy."
    return protected_path(executable)
