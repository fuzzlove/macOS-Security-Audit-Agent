from __future__ import annotations

from mac_audit_agent.network_intelligence.models import NetworkPosture

VPN_PREFIXES = ("utun", "ppp", "ipsec", "tun", "tap")


def parse_ifconfig_vpn(text: str) -> tuple[bool, str]:
    names: list[str] = []
    for line in text.splitlines():
        if not line or line.startswith("\t") or ":" not in line:
            continue
        name = line.split(":", 1)[0]
        if name.startswith(VPN_PREFIXES) and "UP" in line:
            names.append(name)
    return bool(names), ", ".join(names)


def parse_proxy_state(text: str) -> tuple[bool, str]:
    enabled_lines = [line.strip() for line in text.splitlines() if "Enabled: Yes" in line or "Proxy Enabled: 1" in line]
    return bool(enabled_lines), "; ".join(enabled_lines)


class VPNProxyCollector:
    def __init__(self, runner) -> None:
        self.runner = runner

    def collect(self) -> tuple[NetworkPosture, list[str]]:
        errors: list[str] = []
        ifconfig = self.runner(["/sbin/ifconfig"])
        proxy = self.runner(["/usr/sbin/networksetup", "-getwebproxy", "Wi-Fi"])
        if ifconfig.returncode != 0:
            errors.append(f"ifconfig VPN collection failed: {(ifconfig.stderr or ifconfig.stdout).strip()}")
        if proxy.returncode != 0:
            errors.append(f"proxy collection failed: {(proxy.stderr or proxy.stdout).strip()}")
        vpn_active, vpn_name = parse_ifconfig_vpn(ifconfig.stdout if ifconfig.returncode == 0 else "")
        proxy_enabled, proxy_details = parse_proxy_state(proxy.stdout if proxy.returncode == 0 else "")
        return NetworkPosture(vpn_active=vpn_active, vpn_name=vpn_name, proxy_enabled=proxy_enabled, proxy_details=proxy_details), errors
