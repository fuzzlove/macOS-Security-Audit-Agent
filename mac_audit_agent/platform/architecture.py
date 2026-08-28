"""Native hardware, process, interpreter, universal2 and Rosetta detection."""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass


def _run(arguments: list[str], timeout: float = 3.0) -> tuple[int | None, str, str]:
    try:
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout, check=False)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "", f"{type(exc).__name__}: {exc}"


@dataclass(frozen=True)
class ArchitectureInfo:
    native_hardware: str
    process: str
    python: str
    executable_architectures: tuple[str, ...]
    universal2_interpreter: bool
    rosetta_translated: bool
    native_execution: bool
    evidence: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def detect_architecture() -> ArchitectureInfo:
    process = platform.machine().lower() or "unknown"
    translated_code, translated_text, translated_error = _run(["/usr/sbin/sysctl", "-n", "sysctl.proc_translated"])
    translated = translated_code == 0 and translated_text == "1"
    arm_code, arm_text, arm_error = _run(["/usr/sbin/sysctl", "-n", "hw.optional.arm64"])
    if process == "arm64":
        native = "arm64"
    elif arm_code == 0 and arm_text == "1":
        native = "arm64"
    elif sys.platform == "darwin":
        native = "x86_64"
    else:
        native = process
    lipo_code, lipo_text, lipo_error = _run(["/usr/bin/lipo", "-archs", os.path.realpath(sys.executable)])
    architectures = tuple(part for part in lipo_text.split() if part in {"arm64", "x86_64"}) if lipo_code == 0 else (process,)
    universal2 = {"arm64", "x86_64"}.issubset(architectures)
    return ArchitectureInfo(native, process, process, architectures, universal2, translated, not translated and process == native, {"sysctl_proc_translated": translated_text, "sysctl_proc_translated_error": translated_error, "hw_optional_arm64": arm_text, "hw_optional_arm64_error": arm_error, "lipo_output": lipo_text, "lipo_error": lipo_error})


__all__ = ["ArchitectureInfo", "detect_architecture"]
