from __future__ import annotations

import platform
from dataclasses import asdict, dataclass


def _parts(value: str) -> tuple[int, ...]:
    try: return tuple(int(item) for item in value.split(".") if item.isdigit())
    except ValueError: return ()


@dataclass(frozen=True)
class MacOSVersionInfo:
    version: str; kernel: str; minimum_supported: str; supported: bool; reason_code: str
    def to_dict(self) -> dict[str, object]: return asdict(self)


def detect_macos_version(minimum: tuple[int, int] = (12, 0)) -> MacOSVersionInfo:
    version = platform.mac_ver()[0]
    if platform.system() != "Darwin": return MacOSVersionInfo(version, platform.release(), ".".join(map(str, minimum)), False, "UNSUPPORTED_OS")
    parsed = _parts(version)
    supported = bool(parsed) and parsed >= minimum
    return MacOSVersionInfo(version, platform.release(), ".".join(map(str, minimum)), supported, "AVAILABLE" if supported else "UNSUPPORTED_OS")


__all__ = ["MacOSVersionInfo", "detect_macos_version"]
