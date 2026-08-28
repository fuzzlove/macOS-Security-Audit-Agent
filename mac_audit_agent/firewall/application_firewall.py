from __future__ import annotations

import shlex
from dataclasses import asdict, dataclass
from pathlib import Path

from mac_audit_agent.performance.subprocess_runner import run_bounded_command

SOCKETFILTERFW = Path("/usr/libexec/ApplicationFirewall/socketfilterfw")
SETTINGS_URL = "x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall"

@dataclass(frozen=True)
class ApplicationFirewallStatus:
    available: bool
    enabled: bool | None
    global_state: str
    stealth_mode: str
    block_all: str
    signed_apps: str
    downloaded_signed_apps: str
    applications: str
    errors: tuple[str, ...] = ()
    def to_dict(self): return asdict(self)

def inspect_application_firewall(*, include_applications: bool = True) -> ApplicationFirewallStatus:
    if not SOCKETFILTERFW.is_file():
        return ApplicationFirewallStatus(False, None, "", "", "", "", "", "", ("socketfilterfw unavailable",))
    switches = ["--getglobalstate", "--getstealthmode", "--getblockall", "--getallowsigned", "--getallowsignedapp"]
    if include_applications: switches.append("--listapps")
    values: dict[str, str] = {}; errors: list[str] = []
    for switch in switches:
        result = run_bounded_command([str(SOCKETFILTERFW), switch], timeout_seconds=8, max_output_bytes=524288, env={"LC_ALL": "C"})
        values[switch] = result.stdout.strip()
        if result.returncode: errors.append(f"{switch}: {result.stderr.strip() or result.error or 'command failed'}")
    global_state = values.get("--getglobalstate", ""); lowered = global_state.lower()
    enabled = True if "enabled" in lowered and "disabled" not in lowered else (False if "disabled" in lowered else None)
    return ApplicationFirewallStatus(True, enabled, global_state, values.get("--getstealthmode", ""), values.get("--getblockall", ""), values.get("--getallowsigned", ""), values.get("--getallowsignedapp", ""), values.get("--listapps", ""), tuple(errors))

def sudo_application_firewall_command(enabled: bool) -> str:
    return shlex.join(["sudo", str(SOCKETFILTERFW), "--setglobalstate", "on" if enabled else "off"])
