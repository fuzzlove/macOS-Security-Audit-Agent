from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from mac_audit_agent.models import utc_now_iso


LOCALHOST_TARGET = "127.0.0.1"
NMAP_INSTALL_MESSAGE = "Nmap is required for enhanced TCP/UDP scanning. Install with: brew install nmap"
NMAP_CREDIT_TEXT = (
    "TCP/UDP scan functionality can optionally use Nmap as an external scanning engine. "
    "Nmap is a separate open-source project maintained by the Nmap Project. "
    "MSAA invokes Nmap locally as a wrapper when available."
)
NMAP_URL = "https://nmap.org/"


@dataclass(frozen=True)
class NmapScanProfile:
    key: str
    label: str
    args: list[str]
    timeout_seconds: int
    estimated_time: str
    requires_sudo: bool
    warning: str = ""


@dataclass
class NmapPortFinding:
    host: str
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    reason: str = ""
    confidence: str = "medium"
    source: str = "nmap"
    scan_profile: str = ""
    command_used_redacted: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


SCAN_PROFILES: dict[str, NmapScanProfile] = {
    "localhost_tcp_quick": NmapScanProfile(
        key="localhost_tcp_quick",
        label="Localhost TCP Quick",
        args=["-sT", "-Pn", "-n", "--top-ports", "1000", LOCALHOST_TARGET, "-oX", "-"],
        timeout_seconds=120,
        estimated_time="Usually under 2 minutes",
        requires_sudo=False,
    ),
    "localhost_tcp_full": NmapScanProfile(
        key="localhost_tcp_full",
        label="Localhost TCP Full",
        args=["-sT", "-Pn", "-n", "-p", "1-65535", LOCALHOST_TARGET, "-oX", "-"],
        timeout_seconds=600,
        estimated_time="Up to 10 minutes",
        requires_sudo=False,
    ),
    "localhost_udp_quick": NmapScanProfile(
        key="localhost_udp_quick",
        label="Localhost UDP Quick",
        args=["-sU", "-Pn", "-n", "--top-ports", "100", LOCALHOST_TARGET, "-oX", "-"],
        timeout_seconds=900,
        estimated_time="UDP scans can be slow",
        requires_sudo=True,
        warning="UDP scans can be slow and may require sudo/root privileges.",
    ),
    "localhost_udp_full": NmapScanProfile(
        key="localhost_udp_full",
        label="Localhost UDP Full",
        args=["-sU", "-Pn", "-n", "-p", "1-65535", LOCALHOST_TARGET, "-oX", "-"],
        timeout_seconds=3600,
        estimated_time="Full UDP scans may take a long time",
        requires_sudo=True,
        warning="Full UDP scans may take a long time and may require sudo/root privileges.",
    ),
}
DEFAULT_SCAN_PROFILE = "localhost_tcp_quick"


@dataclass
class NmapScanResult:
    profile_key: str
    profile_label: str
    target: str
    nmap_path: str
    command_used: list[str]
    command_used_redacted: str
    timestamp: str
    ports: list[NmapPortFinding]
    raw_xml: str = ""
    warnings: list[str] | None = None
    errors: list[str] | None = None
    timed_out: bool = False
    exit_code: int | None = None
    sudo_required: bool = False
    fallback_used: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["ports"] = [port.to_dict() for port in self.ports]
        data["warnings"] = list(self.warnings or [])
        data["errors"] = list(self.errors or [])
        return data


def find_nmap_binary() -> str | None:
    for candidate in ["/opt/homebrew/bin/nmap", "/usr/local/bin/nmap", "/usr/bin/nmap"]:
        if Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    path_candidate = shutil.which("nmap")
    return path_candidate


def validate_target(target: str, *, advanced_authorized: bool = False) -> str:
    normalized = (target or LOCALHOST_TARGET).strip()
    if normalized in {LOCALHOST_TARGET, "localhost", "::1"}:
        return LOCALHOST_TARGET
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError as exc:
        raise ValueError("Nmap scan target must be localhost unless Advanced Authorized Scan Mode is enabled.") from exc
    if address.is_loopback:
        return LOCALHOST_TARGET
    if not advanced_authorized:
        raise ValueError("Non-localhost Nmap targets require Advanced Authorized Scan Mode confirmation.")
    return normalized


def profile_for_scan(scan_mode: str = "safe", protocol: str = "tcp") -> str:
    normalized_mode = str(scan_mode).strip().lower()
    normalized_protocol = str(protocol).strip().lower()
    if normalized_protocol == "udp":
        return "localhost_udp_full" if normalized_mode == "full_udp" else "localhost_udp_quick"
    if normalized_protocol == "both":
        return "localhost_tcp_full" if normalized_mode in {"aggressive", "full", "full_tcp"} else "localhost_tcp_quick"
    if normalized_mode in {"aggressive", "full", "full_tcp"}:
        return "localhost_tcp_full"
    return DEFAULT_SCAN_PROFILE


def command_for_profile(profile_key: str, nmap_path: str, *, target: str = LOCALHOST_TARGET, advanced_authorized: bool = False) -> list[str]:
    profile = SCAN_PROFILES[profile_key]
    safe_target = validate_target(target, advanced_authorized=advanced_authorized)
    args = [safe_target if arg == LOCALHOST_TARGET else arg for arg in profile.args]
    if profile.requires_sudo and os.geteuid() != 0:
        return ["sudo", nmap_path, *args]
    return [nmap_path, *args]


def redact_command(command: list[str]) -> str:
    if not command:
        return ""
    redacted = list(command)
    if redacted[0] == "sudo" and len(redacted) > 1:
        redacted[1] = Path(redacted[1]).name
    else:
        redacted[0] = Path(redacted[0]).name
    return " ".join(redacted)


def parse_nmap_xml(xml_text: str, *, scan_profile: str, command_used_redacted: str, timestamp: str | None = None) -> list[NmapPortFinding]:
    if not xml_text.strip():
        return []
    root = ElementTree.fromstring(xml_text)
    findings: list[NmapPortFinding] = []
    observed_at = timestamp or utc_now_iso()
    for host_node in root.findall("host"):
        addresses = host_node.findall("address")
        host = ""
        for address_node in addresses:
            if address_node.attrib.get("addrtype") in {"ipv4", "ipv6"}:
                host = address_node.attrib.get("addr", "")
                break
        if not host and addresses:
            host = addresses[0].attrib.get("addr", "")
        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            state = state_node.attrib.get("state", "") if state_node is not None else ""
            service = service_node.attrib if service_node is not None else {}
            findings.append(
                NmapPortFinding(
                    host=host,
                    port=int(port_node.attrib.get("portid", "0")),
                    protocol=port_node.attrib.get("protocol", ""),
                    state=state,
                    service=service.get("name", ""),
                    product=service.get("product", ""),
                    version=service.get("version", ""),
                    extra_info=service.get("extrainfo", ""),
                    reason=state_node.attrib.get("reason", "") if state_node is not None else "",
                    confidence="high" if state == "open" else "medium",
                    scan_profile=scan_profile,
                    command_used_redacted=command_used_redacted,
                    timestamp=observed_at,
                )
            )
    return findings


def run_nmap_scan(
    profile_key: str = DEFAULT_SCAN_PROFILE,
    *,
    target: str = LOCALHOST_TARGET,
    advanced_authorized: bool = False,
    timeout_seconds: int | None = None,
    nmap_path: str | None = None,
) -> NmapScanResult:
    if profile_key not in SCAN_PROFILES:
        raise ValueError(f"Unknown Nmap scan profile: {profile_key}")
    profile = SCAN_PROFILES[profile_key]
    safe_target = validate_target(target, advanced_authorized=advanced_authorized)
    resolved_nmap = nmap_path or find_nmap_binary()
    timestamp = utc_now_iso()
    warnings = [profile.warning] if profile.warning else []
    if resolved_nmap is None:
        return NmapScanResult(
            profile_key=profile.key,
            profile_label=profile.label,
            target=safe_target,
            nmap_path="",
            command_used=[],
            command_used_redacted="",
            timestamp=timestamp,
            ports=[],
            warnings=warnings,
            errors=[NMAP_INSTALL_MESSAGE],
            sudo_required=profile.requires_sudo,
            fallback_used=True,
        )
    command = command_for_profile(profile_key, resolved_nmap, target=safe_target, advanced_authorized=advanced_authorized)
    redacted = redact_command(command)
    try:
        completed = subprocess.run(
            command,
            shell=False,
            timeout=timeout_seconds or profile.timeout_seconds,
            capture_output=True,
            text=True,
        )
    except subprocess.TimeoutExpired as exc:
        partial_xml = exc.stdout if isinstance(exc.stdout, str) else ""
        return NmapScanResult(
            profile_key=profile.key,
            profile_label=profile.label,
            target=safe_target,
            nmap_path=resolved_nmap,
            command_used=command,
            command_used_redacted=redacted,
            timestamp=timestamp,
            ports=[],
            raw_xml=partial_xml,
            warnings=warnings,
            errors=[f"Nmap scan timed out after {timeout_seconds or profile.timeout_seconds} seconds."],
            timed_out=True,
            sudo_required=profile.requires_sudo,
        )
    errors: list[str] = []
    if completed.returncode != 0:
        errors.append(completed.stderr.strip() or f"Nmap exited with {completed.returncode}.")
    ports: list[NmapPortFinding] = []
    if completed.stdout.strip():
        try:
            ports = parse_nmap_xml(
                completed.stdout,
                scan_profile=profile.label,
                command_used_redacted=redacted,
                timestamp=timestamp,
            )
        except ElementTree.ParseError as exc:
            errors.append(f"Unable to parse Nmap XML output: {exc}")
    return NmapScanResult(
        profile_key=profile.key,
        profile_label=profile.label,
        target=safe_target,
        nmap_path=resolved_nmap,
        command_used=command,
        command_used_redacted=redacted,
        timestamp=timestamp,
        ports=ports,
        raw_xml=completed.stdout,
        warnings=warnings,
        errors=errors,
        exit_code=completed.returncode,
        sudo_required=profile.requires_sudo,
    )
