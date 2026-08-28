from __future__ import annotations

import plistlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SYSTEM_CONFIG = Path("/Library/Managed Preferences/com.msaa.clickfix.plist")
USER_CONFIG = Path.home() / "Library/Preferences/com.msaa.clickfix.plist"


@dataclass(frozen=True)
class ShellGuardConfig:
    mode: str = "audit"
    warn_threshold: int = 4
    block_threshold: int = 7
    scanner_timeout_ms: int = 100
    maximum_command_bytes: int = 128 * 1024
    maximum_decode_bytes: int = 128 * 1024
    maximum_decode_depth: int = 2
    notifications_enabled: bool = True
    local_json_log_enabled: bool = True
    unified_log_enabled: bool = True
    generic_proxy_enabled: bool = False
    exact_hash_allowlist: tuple[str, ...] = ()
    disabled_rule_ids: tuple[str, ...] = ()
    configuration_version: str = "1"
    source: str = "defaults"


def _validated(data: dict[str, Any], source: str) -> ShellGuardConfig:
    allowed = set(ShellGuardConfig.__dataclass_fields__) - {"source"}
    if set(data) - allowed:
        raise ValueError("configuration contains unsupported fields")
    mode = data.get("mode", "audit")
    if mode not in {"audit", "warn", "block"}: raise ValueError("invalid mode")
    def integer(name: str, default: int, low: int, high: int) -> int:
        value = data.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high: raise ValueError(f"invalid {name}")
        return value
    allow = tuple(data.get("exact_hash_allowlist", ()))
    if any(not isinstance(item, str) or len(item) != 64 or any(c not in "0123456789abcdef" for c in item.lower()) for item in allow): raise ValueError("invalid exact_hash_allowlist")
    disabled = tuple(data.get("disabled_rule_ids", ()))
    if any(not isinstance(item, str) or len(item) > 80 for item in disabled): raise ValueError("invalid disabled_rule_ids")
    for name in ("notifications_enabled", "local_json_log_enabled", "unified_log_enabled", "generic_proxy_enabled"):
        if name in data and not isinstance(data[name], bool): raise ValueError(f"invalid {name}")
    warn_threshold = integer("warn_threshold",4,1,50)
    block_threshold = integer("block_threshold",7,2,100)
    if warn_threshold >= block_threshold:
        raise ValueError("warn_threshold must be lower than block_threshold")
    # A block-level exception is an administrative policy decision. A user plist
    # may tune warnings but cannot authorize an exact command hash bypass.
    effective_allow = tuple(item.lower() for item in allow) if source == "managed_system" else ()
    return ShellGuardConfig(mode=mode, warn_threshold=warn_threshold, block_threshold=block_threshold, scanner_timeout_ms=integer("scanner_timeout_ms",100,10,2000), maximum_command_bytes=integer("maximum_command_bytes",128*1024,1024,1024*1024), maximum_decode_bytes=integer("maximum_decode_bytes",128*1024,1024,1024*1024), maximum_decode_depth=integer("maximum_decode_depth",2,0,4), notifications_enabled=data.get("notifications_enabled",True), local_json_log_enabled=data.get("local_json_log_enabled",True), unified_log_enabled=data.get("unified_log_enabled",True), generic_proxy_enabled=data.get("generic_proxy_enabled",False), exact_hash_allowlist=effective_allow, disabled_rule_ids=disabled, configuration_version=str(data.get("configuration_version","1"))[:64], source=source)


def load_config(system_path: Path = SYSTEM_CONFIG, user_path: Path = USER_CONFIG) -> ShellGuardConfig:
    for path, source in ((system_path, "managed_system"), (user_path, "user")):
        if path.is_file():
            try:
                payload = plistlib.loads(path.read_bytes())
                if not isinstance(payload, dict): raise ValueError("configuration root must be a dictionary")
                return _validated(payload, source)
            except (OSError, ValueError, TypeError, plistlib.InvalidFileException) as exc:
                raise ValueError(f"invalid {source} configuration: {type(exc).__name__}") from exc
    return ShellGuardConfig()
