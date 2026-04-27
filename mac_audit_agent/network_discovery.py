from __future__ import annotations

import ipaddress
import plistlib
import json
import os
import re
import shutil
import socket
import subprocess
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from uuid import uuid4

from mac_audit_agent.config import AuditConfig
from mac_audit_agent.models import (
    Finding,
    NetworkDiscoveryComparison,
    NetworkDiscoveryResult,
    NetworkHostSnapshot,
    RawLogEntry,
    make_finding,
    utc_now_iso,
)


RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

OUI_VENDOR_HINTS = {
    "000c29": "VMware",
    "0003ff": "Parallels",
    "f4f5e8": "Apple",
    "0017f2": "Apple",
    "a4b197": "Apple",
    "b8e856": "Apple",
    "d0c1b1": "Cisco",
    "f4ea67": "Ubiquiti",
    "3c5282": "HP",
    "1c697a": "Brother",
    "44d9e7": "Canon",
    "fc3497": "Epson",
    "00055d": "Microsoft",
    "fca667": "Amazon",
    "e4956e": "Google",
    "b827eb": "Raspberry Pi",
}

COMMON_MDNS_SERVICE_HINTS = {
    "_airplay._tcp": "AirPlay",
    "_raop._tcp": "RAOP",
    "_ipp._tcp": "Printer",
    "_printer._tcp": "Printer",
    "_smb._tcp": "File Sharing",
    "_ssh._tcp": "SSH",
    "_http._tcp": "Web",
    "_https._tcp": "Web",
    "_companion-link._tcp": "Companion Link",
    "_workstation._tcp": "Workstation",
    "_googlecast._tcp": "Cast",
    "_rfb._tcp": "Remote Desktop",
    "_hap._tcp": "HomeKit",
}

PING_SWEEP_MAX_WORKERS = 50
REVERSE_DNS_TIMEOUT_SECONDS = 0.3
APPLE_KEYWORDS = ("apple", "iphone", "ipad", "ipod", "mac", "macbook", "imac", "appletv", "apple tv", "homepod")

SCAN_PROFILES: dict[str, dict[str, object]] = {
    "quick": {
        "label": "Quick Scan",
        "max_workers": 50,
        "ping_limit": 0,
        "ping_retries": 1,
        "use_mdns": True,
        "use_reverse_dns": False,
    },
    "standard": {
        "label": "Standard Discovery",
        "max_workers": 50,
        "ping_limit": 254,
        "ping_retries": 1,
        "use_mdns": True,
        "use_reverse_dns": True,
    },
    "deep": {
        "label": "Deep Discovery",
        "max_workers": 50,
        "ping_limit": 254,
        "ping_retries": 2,
        "use_mdns": True,
        "use_reverse_dns": True,
    },
}


def normalize_mac_address(value: str) -> str:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", value or "").lower()
    if len(cleaned) != 12:
        return (value or "").strip().lower()
    return ":".join(cleaned[index : index + 2] for index in range(0, 12, 2))


def _run_command(argv: list[str], timeout: int = 5) -> str:
    executable = argv[0] if Path(argv[0]).exists() else shutil.which(argv[0])
    if not executable:
        return ""
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (completed.stdout or completed.stderr or "").strip()


def list_local_interfaces() -> list[str]:
    names = []
    try:
        names = [name for _index, name in socket.if_nameindex() if name]
    except OSError:
        names = []
    for fallback in ["en0", "en1", "awdl0", "lo0"]:
        if fallback not in names:
            names.append(fallback)
    return names


def sanitize_interface_name(value: str) -> str:
    candidate = value.strip()
    if not candidate or not re.fullmatch(r"[A-Za-z0-9._-]+", candidate):
        raise ValueError("Interface name is invalid.")
    return candidate


def sanitize_scan_profile(value: str) -> str:
    candidate = (value or "").strip().lower()
    if candidate not in SCAN_PROFILES:
        raise ValueError(f"Unsupported scan profile: {value}")
    return candidate


def _parse_ifconfig_interface(text: str, interface: str) -> dict[str, str]:
    block = ""
    capture = False
    for line in text.splitlines():
        if line.startswith(f"{interface}:"):
            capture = True
            block = line + "\n"
            continue
        if capture and line and not line.startswith("\t"):
            break
        if capture:
            block += line + "\n"
    inet_match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)", block)
    broadcast_match = re.search(r"\bbroadcast\s+(\d+\.\d+\.\d+\.\d+)", block)
    if not inet_match:
        return {}
    netmask = inet_match.group(2)
    if netmask.startswith("0x"):
        value = int(netmask, 16)
        netmask = ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))
    return {
        "ip_address": inet_match.group(1),
        "netmask": netmask,
        "broadcast": broadcast_match.group(1) if broadcast_match else "",
    }


def parse_active_interfaces(text: str) -> list[str]:
    active: list[str] = []
    current_name = ""
    current_up = False
    current_running = False
    current_inet = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        if not line.startswith("\t") and ":" in line:
            if current_name and current_up and current_running and current_inet:
                active.append(current_name)
            current_name = line.split(":", 1)[0].strip()
            flags_text = line
            current_up = "UP" in flags_text
            current_running = "RUNNING" in flags_text
            current_inet = False
            continue
        if current_name and "\tinet " in raw_line:
            current_inet = True
    if current_name and current_up and current_running and current_inet:
        active.append(current_name)
    return active


def detect_preferred_interface() -> str:
    ifconfig_text = _run_command(["ifconfig"], timeout=5)
    active = parse_active_interfaces(ifconfig_text)
    for preferred in ("en0", "en1"):
        if preferred in active:
            return preferred
    if active:
        return active[0]
    names = list_local_interfaces()
    return names[0] if names else "en0"


def parse_arp_table(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        match = re.search(
            r"^(?:(?P<hostname>[^\s(]+)\s+)?\((?P<ip>\d+\.\d+\.\d+\.\d+)\)\s+at\s+(?P<mac>[0-9a-f:]+|<incomplete>)(?:\s+on\s+(?P<iface>[A-Za-z0-9._-]+))?",
            line,
            flags=re.IGNORECASE,
        )
        if not match:
            continue
        rows.append(
            {
                "hostname": "" if (match.group("hostname") or "") == "?" else (match.group("hostname") or ""),
                "ip_address": match.group("ip"),
                "mac_address": "" if match.group("mac") == "<incomplete>" else normalize_mac_address(match.group("mac")),
                "interface": match.group("iface") or "",
                "raw": line.strip(),
            }
        )
    return rows


def parse_netstat_routing(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        if parts[:1] == ["default"] and len(parts) >= 2:
            return parts[1]
    return ""


def _vendor_guess(mac_address: str) -> str:
    if not mac_address:
        return ""
    prefix = re.sub(r"[^0-9a-fA-F]", "", mac_address).lower()[:6]
    return OUI_VENDOR_HINTS.get(prefix, "")


def _lookup_reverse_dns(ip_address: str) -> tuple[str, list[str]]:
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(socket.gethostbyaddr, ip_address)
            hostname, aliases, _addresses = future.result(timeout=REVERSE_DNS_TIMEOUT_SECONDS)
    except (OSError, FutureTimeoutError):
        return "", []
    except Exception:
        return "", []
    candidate = hostname.strip().lower().rstrip(".")
    alias_list = [alias.strip().lower().rstrip(".") for alias in aliases if alias.strip()]
    return candidate, alias_list


def _parse_arp_resolution(text: str, ip_address: str) -> dict[str, str]:
    for row in parse_arp_table(text):
        if row.get("ip_address") == ip_address:
            return row
    return {}


def _resolve_arp_entry(ip_address: str) -> dict[str, str]:
    text = _run_command(["arp", "-n", ip_address], timeout=3)
    row = _parse_arp_resolution(text, ip_address)
    if row:
        return row
    text = _run_command(["arp", "-a"], timeout=5)
    return _parse_arp_resolution(text, ip_address)


def _load_dhcp_lease_cache() -> dict[str, dict[str, str]]:
    cache: dict[str, dict[str, str]] = {}
    lease_dir = Path("/var/db/dhcpclient/leases")
    try:
        exists = lease_dir.exists()
    except OSError:
        return cache
    if not exists:
        return cache
    for lease_path in lease_dir.glob("*"):
        try:
            raw = lease_path.read_bytes()
        except OSError:
            continue
        record: dict[str, object] = {}
        try:
            loaded = plistlib.loads(raw)
            if isinstance(loaded, dict):
                record = loaded
        except Exception:
            text = raw.decode("utf-8", errors="ignore")
            match_ip = re.search(r"(?:IPAddress|ip(?:address)?)\s*[:=]\s*(?P<ip>\d+\.\d+\.\d+\.\d+)", text, flags=re.IGNORECASE)
            match_host = re.search(r"(?:HostName|LeaseHostname|hostname)\s*[:=]\s*(?P<host>[A-Za-z0-9._-]+)", text, flags=re.IGNORECASE)
            if not match_ip and not match_host:
                continue
            record = {}
            if match_ip:
                record["IPAddress"] = match_ip.group("ip")
            if match_host:
                record["HostName"] = match_host.group("host")
        ip_address = str(
            record.get("IPAddress")
            or record.get("ip_address")
            or record.get("IPAddressV4")
            or ""
        ).strip()
        if not ip_address:
            continue
        hostname = str(
            record.get("HostName")
            or record.get("LeaseHostname")
            or record.get("hostname")
            or record.get("ClientName")
            or ""
        ).strip().lower().rstrip(".")
        mac_address = normalize_mac_address(
            str(
                record.get("HardwareAddress")
                or record.get("MACAddress")
                or record.get("ClientIdentifier")
                or record.get("client_identifier")
                or ""
            )
        )
        cache[ip_address] = {
            "hostname": hostname,
            "mac_address": mac_address,
            "source": lease_path.name,
        }
    return cache


def _lookup_smb_name(ip_address: str) -> str:
    text = _run_command(["smbutil", "lookup", ip_address], timeout=3)
    if not text:
        return ""
    patterns = [
        r"(?:machine|netbios|computer)\s+name[:=]\s*(?P<name>[A-Za-z0-9._-]+)",
        r"\bname[:=]\s*(?P<name>[A-Za-z0-9._-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return match.group("name").strip().lower().rstrip(".")
    for token in re.findall(r"[A-Za-z0-9._-]+", text):
        if token and token.lower() not in {"lookup", "status", "for", "address", "name"}:
            return token.strip().lower().rstrip(".")
    return ""


def _parse_mdns_catalog(text: str) -> list[str]:
    services: set[str] = set()
    for line in text.splitlines():
        for match in re.findall(r"(_[A-Za-z0-9.-]+\._(?:tcp|udp))", line, flags=re.IGNORECASE):
            services.add(match.lower())
    return sorted(services)


def _extract_mdns_candidate_names(text: str) -> list[str]:
    candidates: set[str] = set()
    for line in text.splitlines():
        if "Add" not in line:
            continue
        match = re.search(
            r"\sAdd\s+\d+\s+\d+\s+(?P<name>.+?)\s+(?P<service>_[A-Za-z0-9.-]+\._(?:tcp|udp))\.",
            line,
            flags=re.IGNORECASE,
        )
        if not match:
            continue
        raw_name = match.group("name").strip().lower().rstrip(".")
        if not raw_name:
            continue
        cleaned = re.sub(r"[^a-z0-9._ -]+", "", raw_name).strip()
        if cleaned:
            candidates.add(cleaned)
            slug = cleaned.replace(" ", "-")
            if slug:
                candidates.add(slug)
    return sorted(candidates)


def _parse_mdns_service_map(text: str) -> dict[str, list[str]]:
    service_map: dict[str, set[str]] = {}
    for line in text.splitlines():
        match = re.search(
            r"\sAdd\s+\d+\s+\d+\s+(?P<name>.+?)\s+(?P<service>_[A-Za-z0-9.-]+\._(?:tcp|udp))\.",
            line,
            flags=re.IGNORECASE,
        )
        if not match:
            continue
        raw_name = match.group("name").strip().lower().rstrip(".")
        service = match.group("service").strip().lower()
        if not raw_name:
            continue
        normalized_names = {
            raw_name,
            re.sub(r"[^a-z0-9._ -]+", "", raw_name).strip(),
            raw_name.replace(" ", "-"),
        }
        for name in {item for item in normalized_names if item}:
            service_map.setdefault(name, set()).add(service)
    return {key: sorted(value) for key, value in service_map.items()}


def _probe_local_name(candidate: str) -> str:
    candidate = candidate.strip().lower().rstrip(".")
    if not candidate:
        return ""
    try:
        socket.getaddrinfo(f"{candidate}.local", None)
    except OSError:
        return ""
    return f"{candidate}.local"


def _service_names_for_host(hostname: str, vendor: str, mdns_catalog: list[str]) -> list[str]:
    host_lower = hostname.lower()
    vendor_lower = vendor.lower()
    names: list[str] = []
    catalog = set(mdns_catalog)
    if "_airplay._tcp" in catalog and (vendor_lower == "apple" or any(token in host_lower for token in ("iphone", "ipad", "appletv", "apple tv", "homepod", "macbook", "imac"))):
        names.append("AirPlay")
    if "_raop._tcp" in catalog and (vendor_lower == "apple" or any(token in host_lower for token in ("homepod", "speaker", "apple"))):
        names.append("RAOP")
    if (any(service in catalog for service in ("_ipp._tcp", "_printer._tcp")) and any(token in host_lower for token in ("printer", "hp", "brother", "canon", "epson", "xerox"))) or vendor_lower in {"hp", "hewlett-packard", "brother", "canon", "epson", "xerox"}:
        names.append("Printer")
    if "_smb._tcp" in catalog and any(token in host_lower for token in ("nas", "fileserver", "server", "share")):
        names.append("File Sharing")
    if "_ssh._tcp" in catalog and any(token in host_lower for token in ("server", "nas", "router", "pi", "raspberry")):
        names.append("SSH")
    if any(service in catalog for service in ("_http._tcp", "_https._tcp")) and any(token in host_lower for token in ("router", "web", "admin", "gateway")):
        names.append("Web UI")
    if "_companion-link._tcp" in catalog and vendor_lower == "apple":
        names.append("Companion Link")
    if "_googlecast._tcp" in catalog and any(token in host_lower for token in ("cast", "chromecast", "tv")):
        names.append("Cast")
    if "_rfb._tcp" in catalog and any(token in host_lower for token in ("vnc", "remote", "screen")):
        names.append("Remote Desktop")
    if "_workstation._tcp" in catalog and vendor_lower == "apple":
        names.append("Workstation")
    return sorted(set(names))


def _infer_device_type(hostname: str, vendor: str, service_names: list[str]) -> str:
    host_lower = hostname.lower()
    vendor_lower = vendor.lower()
    services = {item.lower() for item in service_names}
    if any(token in host_lower for token in ("iphone", "ipad", "ipod")):
        return "Mobile device"
    if any(token in host_lower for token in ("macbook", "imac", "mac mini", "macmini")):
        return "Apple computer"
    if "airplay" in services or "raop" in services:
        if any(token in host_lower for token in ("tv", "appletv", "apple tv")):
            return "Apple TV"
        if any(token in host_lower for token in ("homepod", "speaker")):
            return "Speaker"
        return "Apple media device"
    if "printer" in services or any(token in host_lower for token in ("printer", "hp", "brother", "canon", "epson", "xerox")) or vendor_lower in {"hp", "hewlett-packard", "brother", "canon", "epson", "xerox"}:
        return "Printer"
    if "file sharing" in services or "smb" in services or any(token in host_lower for token in ("nas", "fileserver", "file", "share")):
        return "NAS / File server"
    if "web ui" in services or any(token in host_lower for token in ("router", "gateway", "admin", "web")):
        return "Network appliance"
    if "cast" in services or any(token in host_lower for token in ("chromecast", "cast", "tv")):
        return "Media device"
    if "ssh" in services or any(token in host_lower for token in ("server", "vm", "rpi", "raspberry", "linux")):
        return "Server / workstation"
    if vendor_lower == "apple":
        return "Apple device"
    if vendor_lower in {"intel", "realtek", "vmware", "parallels"}:
        return "Computer / VM"
    return "Unknown / review"


def _enrich_host_identity(
    host: NetworkHostSnapshot,
    *,
    mdns_catalog: list[str],
    dhcp_cache: dict[str, dict[str, str]],
    use_reverse_dns: bool = True,
) -> NetworkHostSnapshot:
    hostname_candidates: list[tuple[str, str]] = []
    netbios_name = ""
    dhcp_hostname = ""
    mac_address = normalize_mac_address(host.mac_address)
    mac_source = host.mac_source
    hostname = host.hostname.strip().lower().rstrip(".")
    hostname_source = host.hostname_source
    reverse_dns, aliases = _lookup_reverse_dns(host.ip_address) if use_reverse_dns else ("", [])
    if reverse_dns:
        hostname_candidates.append((reverse_dns, "reverse_dns"))
    for alias in aliases:
        hostname_candidates.append((alias, "reverse_dns_alias"))
    arp_row = _resolve_arp_entry(host.ip_address)
    if arp_row.get("mac_address"):
        mac_address = normalize_mac_address(arp_row["mac_address"])
        if not mac_source:
            mac_source = "arp"
    if arp_row.get("hostname"):
        hostname_candidates.append((arp_row["hostname"], "arp"))
    lease = dhcp_cache.get(host.ip_address, {})
    if lease.get("mac_address") and not mac_address:
        mac_address = normalize_mac_address(str(lease["mac_address"]))
        mac_source = "dhcp"
    if lease.get("hostname"):
        dhcp_hostname = str(lease["hostname"]).strip().lower().rstrip(".")
        hostname_candidates.append((dhcp_hostname, "dhcp"))
    smb_name = _lookup_smb_name(host.ip_address)
    if smb_name:
        netbios_name = smb_name
        hostname_candidates.append((smb_name, "smb"))

    confirmed_local_name = ""
    confirmed_local_source = ""
    if hostname:
        hostname_candidates.append((hostname, hostname_source or "existing"))
    for candidate, source in hostname_candidates:
        local_name = _probe_local_name(candidate)
        if local_name:
            confirmed_local_name = local_name
            confirmed_local_source = source
            break
    if not confirmed_local_name:
        local_name = _probe_local_name(host.ip_address)
        if local_name:
            confirmed_local_name = local_name
            confirmed_local_source = "mdns"

    chosen_hostname = hostname
    chosen_source = hostname_source
    for candidate, source in hostname_candidates:
        cleaned = candidate.strip().lower().rstrip(".")
        if cleaned:
            chosen_hostname = cleaned
            chosen_source = source
            break
    if confirmed_local_name:
        chosen_hostname = confirmed_local_name
        chosen_source = confirmed_local_source or "mdns"

    vendor = host.vendor or host.vendor_guess or _vendor_guess(mac_address)
    derived_service_names = _service_names_for_host(chosen_hostname, vendor, mdns_catalog)
    service_names = sorted(set(host.service_names) | set(derived_service_names))
    device_type = _infer_device_type(chosen_hostname, vendor, service_names)

    enrichment_sources = [item for item in [
        "reverse dns" if reverse_dns else "",
        "arp" if arp_row else "",
        "dhcp" if lease else "",
        "smb" if smb_name else "",
        "mdns" if confirmed_local_name else "",
    ] if item]
    notes_parts = [host.notes] if host.notes else []
    note_items = list(host.note_items)
    if enrichment_sources:
        enrichment_note = f"Enrichment sources: {', '.join(enrichment_sources)}."
        notes_parts.append(enrichment_note)
        note_items.append(enrichment_note)
    if service_names:
        services_note = f"Services: {', '.join(service_names)}."
        notes_parts.append(services_note)
        note_items.append(services_note)
    if device_type:
        type_note = f"Type: {device_type}."
        notes_parts.append(type_note)
        note_items.append(type_note)

    temp_host = NetworkHostSnapshot(
        ip_address=host.ip_address,
        mac_address=mac_address,
        hostname=chosen_hostname,
        likely_hostname="",
        vendor_guess=vendor,
        vendor=vendor,
        reverse_dns=reverse_dns,
        mdns_name=confirmed_local_name,
        netbios_name=netbios_name,
        dhcp_hostname=dhcp_hostname,
        service_names=service_names,
        device_type=device_type,
        hostname_source=chosen_source,
        mac_source=mac_source,
        interface=host.interface,
        discovery_methods=sorted(set(host.discovery_methods + enrichment_sources)),
        gateway=host.gateway,
        first_seen=host.first_seen,
        last_seen=host.last_seen,
        response_time_ms=host.response_time_ms,
        confidence=host.confidence,
        notes=host.notes,
        note_items=note_items,
    )
    likely_hostname = _derive_likely_hostname(temp_host)

    confidence = _confidence_for_host(
        temp_host
    )

    return NetworkHostSnapshot(
        ip_address=host.ip_address,
        mac_address=mac_address,
        hostname=chosen_hostname,
        likely_hostname=likely_hostname,
        vendor_guess=vendor,
        vendor=vendor,
        reverse_dns=reverse_dns,
        mdns_name=confirmed_local_name,
        netbios_name=netbios_name,
        dhcp_hostname=dhcp_hostname,
        service_names=service_names,
        device_type=device_type,
        hostname_source=chosen_source,
        mac_source=mac_source,
        interface=host.interface,
        discovery_methods=sorted(set(host.discovery_methods + enrichment_sources)),
        gateway=host.gateway,
        baseline_status=host.baseline_status,
        first_seen=host.first_seen,
        last_seen=host.last_seen,
        response_time_ms=host.response_time_ms,
        confidence=confidence,
        notes=" ".join(part for part in notes_parts if part).strip(),
        note_items=list(dict.fromkeys([item for item in note_items if item])),
        review_needed=host.review_needed,
        review_flags=list(dict.fromkeys(host.review_flags)),
    )


def detect_network_scope(interface: str) -> dict[str, str]:
    ifconfig_text = _run_command(["ifconfig", interface], timeout=5)
    details = _parse_ifconfig_interface(ifconfig_text, interface)
    if not details:
        raise ValueError(f"No IPv4 address could be detected for interface {interface}.")
    network = ipaddress.ip_network(f"{details['ip_address']}/{details['netmask']}", strict=False)
    gateway = parse_netstat_routing(_run_command(["netstat", "-rn"], timeout=5))
    scope = "private" if any(network.subnet_of(candidate) for candidate in RFC1918_NETWORKS) else "public"
    return {
        "interface": interface,
        "ip_address": details["ip_address"],
        "netmask": details["netmask"],
        "broadcast": details.get("broadcast", ""),
        "subnet": str(network),
        "gateway": gateway,
        "scope": scope,
    }


def _merge_host(existing: NetworkHostSnapshot | None, incoming: NetworkHostSnapshot) -> NetworkHostSnapshot:
    if existing is None:
        return incoming
    methods = sorted(set(existing.discovery_methods) | set(incoming.discovery_methods))
    confidence_order = {"low": 0, "medium": 1, "high": 2}
    confidence = existing.confidence if confidence_order[existing.confidence] >= confidence_order[incoming.confidence] else incoming.confidence
    mac_address = existing.mac_address or incoming.mac_address
    hostname = existing.hostname or incoming.hostname
    likely_hostname = existing.likely_hostname or incoming.likely_hostname or ""
    vendor_guess = existing.vendor_guess or incoming.vendor_guess
    vendor = existing.vendor or incoming.vendor or vendor_guess
    reverse_dns = existing.reverse_dns or incoming.reverse_dns
    mdns_name = existing.mdns_name or incoming.mdns_name
    netbios_name = existing.netbios_name or incoming.netbios_name
    dhcp_hostname = existing.dhcp_hostname or incoming.dhcp_hostname
    service_names = sorted(set(existing.service_names) | set(incoming.service_names))
    device_type = existing.device_type or incoming.device_type
    hostname_source = existing.hostname_source or incoming.hostname_source
    mac_source = existing.mac_source or incoming.mac_source
    response_time_ms = existing.response_time_ms
    if incoming.response_time_ms is not None and (response_time_ms is None or incoming.response_time_ms < response_time_ms):
        response_time_ms = incoming.response_time_ms
    first_seen = min(existing.first_seen, incoming.first_seen)
    last_seen = max(existing.last_seen, incoming.last_seen)
    notes = "; ".join(part for part in [existing.notes, incoming.notes] if part)
    note_items = list(dict.fromkeys([*existing.note_items, *incoming.note_items]))
    review_flags = list(dict.fromkeys([*existing.review_flags, *incoming.review_flags]))
    return NetworkHostSnapshot(
        ip_address=existing.ip_address,
        mac_address=mac_address,
        hostname=hostname,
        likely_hostname=likely_hostname,
        vendor_guess=vendor_guess,
        vendor=vendor,
        reverse_dns=reverse_dns,
        mdns_name=mdns_name,
        netbios_name=netbios_name,
        dhcp_hostname=dhcp_hostname,
        service_names=service_names,
        device_type=device_type,
        hostname_source=hostname_source,
        mac_source=mac_source,
        interface=incoming.interface or existing.interface,
        discovery_methods=methods,
        gateway=existing.gateway or incoming.gateway,
        baseline_status=existing.baseline_status or incoming.baseline_status,
        first_seen=first_seen,
        last_seen=last_seen,
        response_time_ms=response_time_ms,
        confidence=confidence,
        notes=notes,
        note_items=note_items,
        review_needed=existing.review_needed or incoming.review_needed,
        review_flags=review_flags,
    )


def _ping_host(ip_address: str, rate_limit_seconds: float = 0.01, retries: int = 1) -> tuple[bool, float | None]:
    attempts = max(1, retries)
    best_elapsed_ms: float | None = None
    for _attempt in range(attempts):
        start = time.perf_counter()
        try:
            completed = subprocess.run(["ping", "-c", "1", "-W", "250", ip_address], capture_output=True, text=True, timeout=1, check=False)
        except (OSError, subprocess.TimeoutExpired):
            time.sleep(rate_limit_seconds)
            continue
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        time.sleep(rate_limit_seconds)
        if completed.returncode == 0:
            if best_elapsed_ms is None or elapsed_ms < best_elapsed_ms:
                best_elapsed_ms = elapsed_ms
            return True, best_elapsed_ms
    return False, None


def _parse_ping_hostname(output: str) -> str:
    match = re.search(r"PING\s+[^\s]+\s+\((?P<hostname>[^)]+)\)", output)
    return match.group("hostname") if match else ""


def _run_mdns_probe() -> str:
    return _run_command(["dns-sd", "-B", "_services._dns-sd._udp"], timeout=3)


def _run_smb_probe() -> str:
    return _run_command(["smbutil", "status", "-ae"], timeout=3)


def _run_neighbor_probe() -> str:
    text = _run_command(["arp", "-anl"], timeout=3)
    if parse_arp_table(text):
        return text
    return _run_command(["ndp", "-an"], timeout=3)


def _resolve_mdns_host(candidate: str, subnet: ipaddress.IPv4Network) -> list[tuple[str, str]]:
    cleaned = candidate.strip().lower().rstrip(".")
    if not cleaned:
        return []
    lookup_name = cleaned if cleaned.endswith(".local") else f"{cleaned}.local"
    try:
        answers = socket.getaddrinfo(lookup_name, None)
    except OSError:
        return []
    results: set[tuple[str, str]] = set()
    for _family, _socktype, _proto, _canonname, sockaddr in answers:
        if not sockaddr:
            continue
        ip_address = str(sockaddr[0]).strip()
        try:
            ip_obj = ipaddress.ip_address(ip_address)
        except ValueError:
            continue
        if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in subnet:
            results.add((ip_address, lookup_name))
    return sorted(results)


def _collect_mdns_hosts(
    *,
    current_hosts: list[NetworkHostSnapshot],
    subnet: ipaddress.IPv4Network,
    interface: str,
    timestamp: str,
    mdns_text: str,
    dhcp_cache: dict[str, dict[str, str]],
) -> tuple[list[NetworkHostSnapshot], list[str]]:
    candidates: set[str] = set(_extract_mdns_candidate_names(mdns_text))
    service_map = _parse_mdns_service_map(mdns_text)
    current_by_ip = {host.ip_address: host for host in current_hosts}
    for host in current_hosts:
        if host.hostname:
            candidates.add(host.hostname)
        if host.vendor_guess.lower() == "apple" or any(token in host.hostname.lower() for token in APPLE_KEYWORDS):
            ip_candidate = host.ip_address.split(".")[-1]
            if ip_candidate:
                candidates.add(ip_candidate)
    for lease in dhcp_cache.values():
        hostname = str(lease.get("hostname", "")).strip().lower().rstrip(".")
        if hostname:
            candidates.add(hostname)

    mdns_hosts: list[NetworkHostSnapshot] = []
    resolved_names: list[str] = []
    for candidate in sorted(candidates):
        for ip_address, hostname in _resolve_mdns_host(candidate, subnet):
            seed = current_by_ip.get(ip_address)
            vendor_guess = seed.vendor_guess if seed else ""
            mdns_services = service_map.get(candidate, []) or service_map.get(hostname, [])
            mdns_hosts.append(
                NetworkHostSnapshot(
                    ip_address=ip_address,
                    mac_address=seed.mac_address if seed else "",
                    hostname=hostname,
                    vendor_guess=vendor_guess,
                    vendor=vendor_guess,
                    mdns_name=hostname,
                    interface=interface,
                    discovery_methods=["mdns"],
                    first_seen=timestamp,
                    last_seen=timestamp,
                    response_time_ms=seed.response_time_ms if seed else None,
                    confidence="high" if vendor_guess.lower() == "apple" or seed else "medium",
                    notes="Resolved via mDNS (.local).",
                    hostname_source="mdns",
                    mac_source=seed.mac_source if seed else "",
                    service_names=[COMMON_MDNS_SERVICE_HINTS.get(item, item) for item in mdns_services],
                )
            )
            resolved_names.append(hostname)
    return mdns_hosts, sorted(set(resolved_names))


def _run_ping_sweep(
    targets: list[str],
    *,
    interface: str,
    timestamp: str,
    max_workers: int,
    retries: int,
    progress_callback: Callable[[dict[str, object]], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> tuple[list[NetworkHostSnapshot], int]:
    if not targets:
        return [], 0
    workers = max(1, min(max_workers, len(targets)))
    discovered: list[NetworkHostSnapshot] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_ping_host, ip_address, 0.01, retries): ip_address for ip_address in targets}
        completed_count = 0
        for future in as_completed(futures):
            if cancel_check is not None and cancel_check():
                for pending in futures:
                    pending.cancel()
                raise RuntimeError("Network discovery cancelled.")
            ip_address = futures[future]
            try:
                responded, response_time_ms = future.result()
            except Exception:
                completed_count += 1
                _report_progress(
                    progress_callback,
                    stage="ping",
                    completed=completed_count,
                    total=len(targets),
                    message=f"Scanning {completed_count}/{len(targets)} hosts.",
                )
                continue
            completed_count += 1
            if not responded:
                _report_progress(
                    progress_callback,
                    stage="ping",
                    completed=completed_count,
                    total=len(targets),
                    message=f"Scanning {completed_count}/{len(targets)} hosts.",
                )
                continue
            discovered.append(
                NetworkHostSnapshot(
                    ip_address=ip_address,
                    mac_address="",
                    hostname="",
                    vendor_guess="",
                    vendor="",
                    interface=interface,
                    discovery_methods=["ping"],
                    first_seen=timestamp,
                    last_seen=timestamp,
                    response_time_ms=response_time_ms,
                    confidence="low",
                    notes="Responded to ping sweep.",
                )
            )
            _report_progress(
                progress_callback,
                stage="ping",
                completed=completed_count,
                total=len(targets),
                message=f"Scanning {completed_count}/{len(targets)} hosts.",
            )
    return discovered, len(targets)


def _report_progress(
    progress_callback: Callable[[dict[str, object]], None] | None,
    *,
    stage: str,
    completed: int,
    total: int,
    message: str,
) -> None:
    if progress_callback is None:
        return
    progress_callback(
        {
            "stage": stage,
            "completed": completed,
            "total": total,
            "message": message,
        }
    )


def _ensure_not_cancelled(cancel_check: Callable[[], bool] | None) -> None:
    if cancel_check is not None and cancel_check():
        raise RuntimeError("Network discovery cancelled.")


def _limit_scan_subnet(network: ipaddress.IPv4Network, local_ip_address: str) -> ipaddress.IPv4Network:
    if network.prefixlen >= 24 or not local_ip_address:
        return network
    return ipaddress.ip_network(f"{local_ip_address}/24", strict=False)


def _select_ping_targets(
    subnet: ipaddress.IPv4Network,
    *,
    skip_ips: set[str],
    ping_limit: int,
) -> list[str]:
    targets = [str(host_ip) for host_ip in subnet.hosts() if str(host_ip) not in skip_ips]
    return targets[: max(0, ping_limit)]


def _upsert_host(hosts: list[NetworkHostSnapshot], incoming: NetworkHostSnapshot) -> None:
    if incoming.mac_address:
        normalized_mac = normalize_mac_address(incoming.mac_address)
        incoming.mac_address = normalized_mac
        for index, host in enumerate(hosts):
            if host.mac_address and normalize_mac_address(host.mac_address) == normalized_mac:
                hosts[index] = _merge_host(host, incoming)
                return
    for index, host in enumerate(hosts):
        if host.ip_address == incoming.ip_address:
            hosts[index] = _merge_host(host, incoming)
            return
    if incoming.hostname:
        normalized_host = incoming.hostname.strip().lower().rstrip(".")
        for index, host in enumerate(hosts):
            if host.hostname and host.hostname.strip().lower().rstrip(".") == normalized_host:
                hosts[index] = _merge_host(host, incoming)
                return
    hosts.append(incoming)


def _host_ip_set(hosts: list[NetworkHostSnapshot]) -> set[str]:
    return {host.ip_address for host in hosts if host.ip_address}


def _confidence_for_host(host: NetworkHostSnapshot) -> str:
    methods = {item.lower() for item in host.discovery_methods if item}
    source_count = len(methods)
    if host.reverse_dns:
        source_count += 1
    if host.mdns_name:
        source_count += 1
    if host.hostname_source and host.hostname_source not in methods:
        source_count += 1
    if host.mac_source and host.mac_source not in methods:
        source_count += 1
    has_vendor = bool(host.vendor_guess)
    has_mac = bool(host.mac_address)
    if has_mac and (host.hostname or host.mdns_name or host.reverse_dns):
        return "high"
    if has_mac and has_vendor:
        return "medium"
    if host.ip_address and (host.hostname or host.reverse_dns):
        return "medium"
    return "low"


def _vendor_device_fallback(vendor: str, device_type: str) -> str:
    vendor_clean = vendor.strip()
    device_clean = device_type.strip()
    if not vendor_clean and not device_clean:
        return "Unknown Host"
    if vendor_clean and device_clean:
        if vendor_clean.lower() == "apple" and "apple" in device_clean.lower():
            return "Unknown Apple Device"
        if device_clean.lower().startswith("unknown"):
            return device_clean
        return f"Unknown {vendor_clean} {device_clean}"
    if vendor_clean:
        return f"Unknown {vendor_clean} Device"
    return f"Unknown {device_clean}"


def _derive_likely_hostname(host: NetworkHostSnapshot) -> str:
    candidates = [
        host.mdns_name,
        host.reverse_dns,
        host.netbios_name,
        host.dhcp_hostname,
        host.hostname,
    ]
    for candidate in candidates:
        cleaned = str(candidate or "").strip()
        if cleaned:
            return cleaned
    fallback = _vendor_device_fallback(host.vendor or host.vendor_guess, host.device_type)
    return fallback or "Unknown Host"


def _append_debug(debug_logs: list[str], message: str) -> None:
    debug_logs.append(message)


def _mark_review_needed_hosts(
    hosts: list[NetworkHostSnapshot],
    comparison: NetworkDiscoveryComparison,
    *,
    gateway_ip: str,
    gateway_mac: str,
) -> list[NetworkHostSnapshot]:
    hostname_counts = Counter(host.hostname for host in hosts if host.hostname)
    mac_counts = Counter(host.mac_address for host in hosts if host.mac_address)
    new_ips = {str(item.get("ip_address", "")) for item in comparison.new_devices}
    changed_ip_map = {str(item.get("ip_address", "")): item for item in comparison.changed_mac_for_same_ip}
    changed_mac_map = {str(item.get("mac_address", "")): item for item in comparison.changed_hostname_for_same_mac}
    gateway_changed = bool(comparison.gateway_changed)
    flagged: list[NetworkHostSnapshot] = []
    for host in hosts:
        flags: list[str] = []
        notes = list(host.note_items)
        baseline_status = "matched baseline"
        gateway = bool(host.ip_address == gateway_ip)
        if gateway:
            flags.append("gateway")
            if not host.device_type:
                host.device_type = "Router / Gateway"
        if host.ip_address in new_ips:
            flags.append("new device since last baseline")
            baseline_status = "new device since last baseline"
        if host.mac_address and not (host.vendor or host.vendor_guess):
            flags.append("unknown MAC vendor")
            if baseline_status == "matched baseline":
                baseline_status = "unknown MAC vendor"
        if not host.hostname:
            flags.append("no hostname")
            if baseline_status == "matched baseline":
                baseline_status = "no hostname"
        if host.hostname and hostname_counts[host.hostname] > 1:
            flags.append("duplicate hostname")
            baseline_status = "duplicate hostname"
        if host.mac_address and mac_counts[host.mac_address] > 1:
            flags.append("duplicate MAC")
            baseline_status = "duplicate MAC"
        if host.ip_address in changed_ip_map:
            flags.append("same IP with different MAC")
            baseline_status = "same IP with different MAC"
        if host.mac_address and host.mac_address in changed_mac_map:
            flags.append("same MAC with different hostname")
            baseline_status = "same MAC with different hostname"
        if gateway and gateway_changed:
            flags.append("gateway MAC changed")
            baseline_status = "gateway MAC changed"
        review_needed = any(
            flag in {
                "new device since last baseline",
                "unknown MAC vendor",
                "no hostname",
                "duplicate hostname",
                "duplicate MAC",
                "same IP with different MAC",
                "same MAC with different hostname",
                "gateway MAC changed",
            }
            for flag in flags
        )
        if review_needed:
            notes.append("Review needed.")
        likely_hostname = host.likely_hostname or _derive_likely_hostname(host)
        flagged.append(
            NetworkHostSnapshot(
                ip_address=host.ip_address,
                mac_address=host.mac_address,
                hostname=host.hostname,
                likely_hostname=likely_hostname,
                vendor_guess=host.vendor_guess,
                vendor=host.vendor or host.vendor_guess,
                reverse_dns=host.reverse_dns,
                mdns_name=host.mdns_name,
                netbios_name=host.netbios_name,
                dhcp_hostname=host.dhcp_hostname,
                service_names=list(host.service_names),
                device_type=host.device_type,
                hostname_source=host.hostname_source,
                mac_source=host.mac_source,
                interface=host.interface,
                discovery_methods=list(host.discovery_methods),
                gateway=gateway,
                baseline_status=baseline_status,
                first_seen=host.first_seen,
                last_seen=host.last_seen,
                response_time_ms=host.response_time_ms,
                confidence=host.confidence,
                notes=host.notes or " ".join(notes).strip(),
                note_items=list(dict.fromkeys([item for item in notes if item])),
                review_needed=review_needed,
                review_flags=list(dict.fromkeys(flags)),
            )
        )
    return flagged


def discover_local_network(
    *,
    interface: str,
    scan_profile: str = "standard",
    confirm_public_network: bool = False,
    progress_callback: Callable[[dict[str, object]], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
    previous_hosts: list[NetworkHostSnapshot] | None = None,
    previous_gateway: str = "",
    previous_gateway_mac: str = "",
    previous_subnet: str = "",
) -> tuple[NetworkDiscoveryResult, list[Finding], dict[str, object]]:
    interface = sanitize_interface_name(interface)
    scan_profile = sanitize_scan_profile(scan_profile)
    profile = SCAN_PROFILES[scan_profile]
    _ensure_not_cancelled(cancel_check)
    scope = detect_network_scope(interface)
    if scope["scope"] != "private" and not confirm_public_network:
        raise ValueError("Public or non-RFC1918 ranges require explicit confirmation that this is your local network.")
    subnet = _limit_scan_subnet(ipaddress.ip_network(scope["subnet"], strict=False), str(scope.get("ip_address", "")))

    current_hosts: list[NetworkHostSnapshot] = []
    raw_logs: list[RawLogEntry] = []
    errors: list[str] = []
    debug_logs: list[str] = []
    timestamp = utc_now_iso()
    scan_id = f"network-discovery-{timestamp.replace(':', '').replace('-', '')}"
    _append_debug(debug_logs, f"interface selected: {interface}")
    _append_debug(debug_logs, f"subnet detected: {scope['subnet']} gateway={scope['gateway']} scope={scope['scope']}")
    _report_progress(progress_callback, stage="passive", completed=0, total=3, message="Reading ARP table.")

    arp_text = _run_command(["arp", "-a"], timeout=5)
    if arp_text:
        raw_logs.append(RawLogEntry("network_discovery", "arp -a", timestamp, 0, "", arp_text[:500]))
    arp_rows = parse_arp_table(arp_text)
    _append_debug(debug_logs, f"arp rows parsed: {len(arp_rows)}")
    for row in arp_rows:
        if row["interface"] and row["interface"] != interface:
            continue
        ip_address = row["ip_address"]
        if ipaddress.ip_address(ip_address) not in subnet:
            continue
        methods = ["arp"]
        hostname = row["hostname"]
        mac_address = row["mac_address"]
        host = NetworkHostSnapshot(
            ip_address=ip_address,
            mac_address=mac_address,
            hostname=hostname,
            vendor_guess=_vendor_guess(mac_address),
            vendor=_vendor_guess(mac_address),
            interface=interface,
            discovery_methods=methods,
            first_seen=timestamp,
            last_seen=timestamp,
            response_time_ms=None,
            confidence="high" if mac_address and hostname else "medium" if mac_address else "low",
            notes="Discovered from ARP table.",
        )
        _upsert_host(current_hosts, host)
    _report_progress(progress_callback, stage="passive", completed=1, total=3, message=f"ARP discovered {len(current_hosts)} known hosts.")

    _ensure_not_cancelled(cancel_check)
    neighbor_text = _run_neighbor_probe()
    if neighbor_text:
        raw_logs.append(RawLogEntry("network_discovery", "arp -anl / ndp -an", timestamp, 0, "", neighbor_text[:500]))
    neighbor_rows = parse_arp_table(neighbor_text)
    _append_debug(debug_logs, f"neighbor rows parsed: {len(neighbor_rows)}")
    for row in neighbor_rows:
        if row["interface"] and row["interface"] != interface:
            continue
        ip_address = row["ip_address"]
        if ipaddress.ip_address(ip_address) not in subnet:
            continue
        host = NetworkHostSnapshot(
            ip_address=ip_address,
            mac_address=row["mac_address"],
            hostname=row["hostname"],
            vendor_guess=_vendor_guess(row["mac_address"]),
            vendor=_vendor_guess(row["mac_address"]),
            interface=interface,
            discovery_methods=["neighbor"],
            first_seen=timestamp,
            last_seen=timestamp,
            response_time_ms=None,
            confidence="medium" if row["mac_address"] else "low",
            notes="Discovered from system neighbor table.",
        )
        _upsert_host(current_hosts, host)
    _report_progress(progress_callback, stage="passive", completed=2, total=3, message=f"Neighbor tables expanded discovery to {len(current_hosts)} hosts.")

    mdns_text = ""
    mdns_catalog: list[str] = []
    mdns_resolved_names: list[str] = []
    if bool(profile["use_mdns"]):
        _ensure_not_cancelled(cancel_check)
        _report_progress(progress_callback, stage="passive", completed=2, total=3, message="Resolving mDNS names for local devices.")
        mdns_text = _run_mdns_probe()
        mdns_catalog = _parse_mdns_catalog(mdns_text)
        _append_debug(debug_logs, f"mdns services found: {len(mdns_catalog)}")
        if mdns_text:
            raw_logs.append(RawLogEntry("network_discovery", "dns-sd -B _services._dns-sd._udp", timestamp, 0, "", mdns_text[:500]))
    smb_text = _run_smb_probe()
    if smb_text:
        raw_logs.append(RawLogEntry("network_discovery", "smbutil status -ae", timestamp, 0, "", smb_text[:500]))
    dhcp_cache = _load_dhcp_lease_cache()

    if bool(profile["use_mdns"]):
        mdns_hosts, mdns_resolved_names = _collect_mdns_hosts(
            current_hosts=current_hosts,
            subnet=subnet,
            interface=interface,
            timestamp=timestamp,
            mdns_text=mdns_text,
            dhcp_cache=dhcp_cache,
        )
        for host in mdns_hosts:
            _upsert_host(current_hosts, host)
        _append_debug(debug_logs, f"mdns resolved names: {len(mdns_resolved_names)}")
        _report_progress(progress_callback, stage="passive", completed=3, total=3, message=f"mDNS resolved {len(mdns_resolved_names)} names.")
    else:
        _report_progress(progress_callback, stage="passive", completed=3, total=3, message=f"Passive discovery found {len(current_hosts)} hosts.")

    _ensure_not_cancelled(cancel_check)
    ping_targets = _select_ping_targets(
        subnet,
        skip_ips=_host_ip_set(current_hosts),
        ping_limit=int(profile["ping_limit"]),
    )
    _append_debug(debug_logs, f"ping probes sent: {len(ping_targets)}")
    _report_progress(progress_callback, stage="ping", completed=0, total=max(1, len(ping_targets)), message=f"Scanning {len(ping_targets)} hosts with threaded ping.")
    ping_hosts, host_count = _run_ping_sweep(
        ping_targets,
        interface=interface,
        timestamp=timestamp,
        max_workers=min(int(profile["max_workers"]), PING_SWEEP_MAX_WORKERS),
        retries=int(profile["ping_retries"]),
        progress_callback=progress_callback,
        cancel_check=cancel_check,
    )
    for host in ping_hosts:
        _upsert_host(current_hosts, host)
    _report_progress(progress_callback, stage="ping", completed=len(ping_targets), total=max(1, len(ping_targets)), message=f"Ping sweep found {len(ping_hosts)} responsive hosts.")

    _ensure_not_cancelled(cancel_check)
    host_list = sorted(
        [
            _enrich_host_identity(
                host,
                mdns_catalog=mdns_catalog,
                dhcp_cache=dhcp_cache,
                use_reverse_dns=bool(profile.get("use_reverse_dns", True)),
            )
            for host in current_hosts
        ],
        key=lambda item: item.ip_address,
    )
    reverse_dns_count = sum(1 for host in host_list if host.reverse_dns)
    _append_debug(debug_logs, f"reverse dns count: {reverse_dns_count}")
    _report_progress(progress_callback, stage="merge", completed=len(host_list), total=len(host_list) or 1, message=f"Merged and deduplicated {len(host_list)} hosts.")
    gateway_mac = next((host.mac_address for host in host_list if host.ip_address == scope["gateway"] and host.mac_address), "")
    comparison = _compare_hosts(previous_hosts or [], host_list, scope["gateway"], gateway_mac, previous_gateway, previous_gateway_mac, subnet, previous_subnet)
    host_list = _mark_review_needed_hosts(host_list, comparison, gateway_ip=scope["gateway"], gateway_mac=gateway_mac)
    _append_debug(debug_logs, f"merged device count: {len(host_list)}")
    findings = _build_network_discovery_findings(host_list, comparison, scope)
    if not host_list:
        message = "No devices discovered. Check interface/subnet detection and permissions."
        errors.append(message)
        _append_debug(debug_logs, f"error: {message}")
        findings.append(
            make_finding(
                id=f"{scan_id}-info",
                category="Network Discovery",
                title="No local network devices were discovered",
                severity="info",
                description=message,
                evidence=scope["subnet"],
                command_used="arp -a / ping sweep / netstat / ifconfig",
                remediation_suggestion="If this was unexpected, verify the selected interface and confirm the network is active.",
                warning="Lack of discoveries can reflect isolation, filtering, or a quiet network.",
                evidence_summary=f"interface={interface} subnet={scope['subnet']}",
                raw_evidence_ref=scan_id,
                why_this_matters="A quiet or isolated network can be normal, but it may also mean discovery traffic did not reach the expected segment.",
                false_positive_notes="Sleep states, filtering, or an empty lab network can produce no results.",
                recommended_next_steps="Check interface selection and confirm the network is the one you intended to assess.",
                what_can_go_wrong="Assuming no devices exist when probes were filtered can hide a connectivity or selection mistake.",
            )
        )
    review_needed_count = sum(1 for host in host_list if host.review_needed)
    return NetworkDiscoveryResult(
        scan_id=scan_id,
        timestamp=timestamp,
        interface=interface,
        subnet=scope["subnet"],
        gateway=scope["gateway"],
        gateway_mac=gateway_mac,
        scope=scope["scope"],
        hosts=host_list,
        comparison=comparison,
        raw_logs=raw_logs,
        errors=errors,
    ), findings, {
        "scan_id": scan_id,
        "interface": interface,
        "subnet": scope["subnet"],
        "scan_subnet": str(subnet),
        "gateway": scope["gateway"],
        "gateway_ip": scope["gateway"],
        "gateway_mac": gateway_mac,
        "scope": scope["scope"],
        "host_count": len(host_list),
        "scan_profile": scan_profile,
        "scan_profile_label": str(profile["label"]),
        "mdns_resolved_names": mdns_resolved_names,
        "review_needed_count": review_needed_count,
        "review_needed_hosts": [host.to_dict() for host in host_list if host.review_needed],
        "hosts": [host.to_dict() for host in host_list],
        "devices": [host.to_dict() for host in host_list],
        "comparison": comparison.to_dict(),
        "errors": errors,
        "debug_logs": debug_logs,
        "methods_used": ["arp -a", "arp -anl", "arp -n <ip>", "ping -c 1 -W 250", "socket.gethostbyaddr()", "socket.getaddrinfo(name.local)", "dns-sd -B _services._dns-sd._udp", "smbutil lookup <ip>", "smbutil status -ae", "dhcp leases", "netstat -rn", "ifconfig"],
    }


def _compare_hosts(
    previous_hosts: list[NetworkHostSnapshot],
    current_hosts: list[NetworkHostSnapshot],
    current_gateway: str,
    current_gateway_mac: str,
    previous_gateway: str,
    previous_gateway_mac: str,
    current_subnet: str,
    previous_subnet: str,
) -> NetworkDiscoveryComparison:
    previous_by_ip = {host.ip_address: host for host in previous_hosts}
    previous_by_mac = {host.mac_address: host for host in previous_hosts if host.mac_address}
    current_by_ip = {host.ip_address: host for host in current_hosts}
    current_by_mac = {host.mac_address: host for host in current_hosts if host.mac_address}
    comparison = NetworkDiscoveryComparison()

    for host in current_hosts:
        if host.ip_address not in previous_by_ip:
            comparison.new_devices.append({"ip_address": host.ip_address, "hostname": host.hostname, "mac_address": host.mac_address, "interface": host.interface})
        previous_host = previous_by_ip.get(host.ip_address)
        if previous_host and previous_host.mac_address and host.mac_address and previous_host.mac_address != host.mac_address:
            comparison.changed_mac_for_same_ip.append({"ip_address": host.ip_address, "previous_mac": previous_host.mac_address, "current_mac": host.mac_address})
        if host.mac_address and host.mac_address in previous_by_mac:
            previous_host = previous_by_mac[host.mac_address]
            if previous_host.hostname != host.hostname and host.hostname:
                comparison.changed_hostname_for_same_mac.append({"mac_address": host.mac_address, "previous_hostname": previous_host.hostname, "current_hostname": host.hostname})

    for host in previous_hosts:
        if host.ip_address not in current_by_ip:
            comparison.missing_devices.append({"ip_address": host.ip_address, "hostname": host.hostname, "mac_address": host.mac_address})

    if (previous_gateway and current_gateway and previous_gateway != current_gateway) or (previous_gateway_mac and current_gateway_mac and previous_gateway_mac != current_gateway_mac):
        comparison.gateway_changed.append({
            "previous_gateway": previous_gateway,
            "current_gateway": current_gateway,
            "previous_gateway_mac": previous_gateway_mac,
            "current_gateway_mac": current_gateway_mac,
            "previous_subnet": previous_subnet,
            "current_subnet": current_subnet,
        })
    return comparison


def _build_network_discovery_findings(
    hosts: list[NetworkHostSnapshot],
    comparison: NetworkDiscoveryComparison,
    scope: dict[str, str],
) -> list[Finding]:
    findings: list[Finding] = []
    hostname_counts = Counter(host.hostname for host in hosts if host.hostname)
    mac_counts = Counter(host.mac_address for host in hosts if host.mac_address)
    for host in hosts:
        if not host.hostname:
            findings.append(
                make_finding(
                    id=f"network-{host.ip_address}-no-hostname",
                    category="Network Discovery",
                    title="Device discovered with no hostname",
                    severity="low",
                    description="A local device responded but did not provide a hostname.",
                    evidence=host.ip_address,
                    command_used="arp -a / ping sweep",
                    remediation_suggestion="If you do not recognize the device, investigate it through approved inventory or management tools.",
                    warning="A missing hostname is not proof of compromise.",
                    evidence_summary=f"{host.ip_address} mac={host.mac_address or 'unknown'}",
                    raw_evidence_ref=host.ip_address,
                    why_this_matters="Unknown devices or incomplete metadata may merit review on managed networks.",
                    false_positive_notes="Some devices intentionally suppress hostname information.",
                    recommended_next_steps="Confirm whether the IP is expected for this subnet and interface.",
                    what_can_go_wrong="Treating a missing hostname as malicious can cause unnecessary escalation.",
                )
            )
        if host.vendor_guess == "":
            findings.append(
                make_finding(
                    id=f"network-{host.ip_address}-vendor-unknown",
                    category="Network Discovery",
                    title="Unknown MAC vendor",
                    severity="low",
                    description="The device MAC address could not be matched to a known vendor hint.",
                    evidence=host.mac_address or host.ip_address,
                    command_used="arp -a",
                    remediation_suggestion="Compare the device to inventory records or switch/AP logs if you need stronger attribution.",
                    warning="Unknown vendor is a weak signal and often just means the OUI was not recognized.",
                    evidence_summary=f"{host.ip_address} mac={host.mac_address or 'unknown'}",
                    raw_evidence_ref=host.ip_address,
                    why_this_matters="Unknown vendor information can make it harder to distinguish approved equipment from untracked devices.",
                    false_positive_notes="The built-in OUI hints are incomplete.",
                    recommended_next_steps="Check your asset inventory and network management sources before taking action.",
                    what_can_go_wrong="Misclassifying approved devices can create noise without improving security.",
                )
            )
    for hostname, count in hostname_counts.items():
        if count < 2:
            continue
        findings.append(
            make_finding(
                id=f"network-duplicate-hostname-{hostname}",
                category="Network Discovery",
                title="Duplicate hostname observed",
                severity="low",
                description="More than one device on the subnet used the same hostname.",
                evidence=hostname,
                command_used="arp -a / ping sweep",
                remediation_suggestion="Check whether the hostname is a default name, a cloned device, or an intentional duplicate in your environment.",
                warning="Duplicate hostnames are common and are not proof of compromise.",
                evidence_summary=f"hostname={hostname} count={count}",
                raw_evidence_ref=hostname,
                why_this_matters="Duplicate names can make device identification and inventory more difficult.",
                false_positive_notes="Phones, printers, and lab images may reuse default names.",
                recommended_next_steps="Review the devices with that hostname and confirm which ones are expected.",
                what_can_go_wrong="Relying on hostname alone can lead to misidentification.",
            )
        )
    for mac_address, count in mac_counts.items():
        if count < 2:
            continue
        findings.append(
            make_finding(
                id=f"network-duplicate-mac-{mac_address}",
                category="Network Discovery",
                title="Duplicate MAC observed",
                severity="medium",
                description="More than one discovered host shared the same MAC address.",
                evidence=mac_address,
                command_used="arp -a / ping sweep",
                remediation_suggestion="Validate whether the device is virtualized, cloned, or sharing a MAC due to a network configuration issue.",
                warning="Duplicate MACs can happen in labs and virtualized environments, but they deserve review.",
                evidence_summary=f"mac={mac_address} count={count}",
                raw_evidence_ref=mac_address,
                why_this_matters="A duplicated MAC can affect local switching, address resolution, and host attribution.",
                false_positive_notes="Virtual machines and misconfigured lab systems can legitimately reuse MAC addresses.",
                recommended_next_steps="Check switch or virtualization inventory to see whether the duplication is expected.",
                what_can_go_wrong="Treating every MAC collision as malicious can create unnecessary disruption.",
            )
        )
    for item in comparison.new_devices:
        findings.append(
            make_finding(
                id=f"network-new-{item['ip_address']}",
                category="Network Discovery",
                title="New device detected on local network",
                severity="medium",
                description="A device appeared during the discovery scan and was not present in the previous baseline.",
                evidence=item["ip_address"],
                command_used="arp -a / ping sweep",
                remediation_suggestion="Review whether the device is expected for this subnet and compare it against your asset inventory.",
                warning="A new device is not proof of compromise, but it may be worth investigating.",
                evidence_summary=f"ip={item['ip_address']} hostname={item.get('hostname', '')} mac={item.get('mac_address', '')}",
                raw_evidence_ref=item["ip_address"],
                why_this_matters="New devices can be legitimate, but they can also represent unmanaged or rogue equipment.",
                false_positive_notes="Guests, phones, printers, and IoT devices may appear legitimately.",
                recommended_next_steps="Check whether the device belongs to a known user, team, or management system.",
                what_can_go_wrong="Automatically isolating a legitimate device can interrupt business operations.",
                business_impact="An unknown device on the local network may indicate unmanaged infrastructure, guest access, or an unexpected endpoint touching business systems.",
                local_network_impact="Devices visible on the same subnet can influence local traffic, name resolution, or shared services.",
            )
        )
    for item in comparison.changed_mac_for_same_ip:
        findings.append(
            make_finding(
                id=f"network-mac-change-{item['ip_address']}",
                category="Network Discovery",
                title="MAC address changed for the same IP",
                severity="high",
                description="The same IP address now resolves to a different MAC address than the previous baseline.",
                evidence=item["ip_address"],
                command_used="arp -a / baseline comparison",
                remediation_suggestion="Check whether DHCP reassigned the address, a device was replaced, or a network spoofing issue needs review.",
                warning="This can be benign, but it can also indicate spoofing or a replaced device.",
                evidence_summary=f"ip={item['ip_address']} previous_mac={item['previous_mac']} current_mac={item['current_mac']}",
                raw_evidence_ref=item["ip_address"],
                why_this_matters="A changed MAC for the same IP can affect trust assumptions, inventory, and local routing.",
                false_positive_notes="DHCP renewals, hardware replacement, and virtualization can cause this.",
                recommended_next_steps="Validate the device identity with your network inventory or switch logs.",
                what_can_go_wrong="Responding to a benign reassignment as though it were malicious can break a normal replacement workflow.",
                business_impact="Unexpected IP-to-MAC changes can affect device trust, support workflows, and tracking of business assets.",
                local_network_impact="A changed MAC can influence local network trust and may matter if the address is used by shared services or ACLs.",
            )
        )
    for item in comparison.changed_hostname_for_same_mac:
        findings.append(
            make_finding(
                id=f"network-hostname-change-{item['mac_address']}",
                category="Network Discovery",
                title="Hostname changed for the same MAC",
                severity="low",
                description="The same MAC address now presents a different hostname than before.",
                evidence=item["mac_address"],
                command_used="baseline comparison",
                remediation_suggestion="Check whether the device was renamed, reimaged, or repurposed.",
                warning="Hostname changes are common and not proof of compromise.",
                evidence_summary=f"mac={item['mac_address']} previous={item['previous_hostname']} current={item['current_hostname']}",
                raw_evidence_ref=item["mac_address"],
                why_this_matters="Renamed or reimaged devices may be expected, but the change should match known maintenance.",
                false_positive_notes="Operating system updates and device enrollment can change hostnames.",
                recommended_next_steps="Confirm the device owner and whether the new hostname matches inventory.",
                what_can_go_wrong="Treating every hostname change as hostile can create unnecessary alerts.",
            )
        )
    for item in comparison.missing_devices:
        findings.append(
            make_finding(
                id=f"network-missing-{item['ip_address']}",
                category="Network Discovery",
                title="Previously seen device is no longer visible",
                severity="low",
                description="A host present in the previous baseline was not observed during this scan.",
                evidence=item["ip_address"],
                command_used="baseline comparison",
                remediation_suggestion="Confirm whether the device is offline, moved, or intentionally removed from the network.",
                warning="Missing devices are often benign and can simply be powered off or disconnected.",
                evidence_summary=f"ip={item['ip_address']} hostname={item.get('hostname', '')} mac={item.get('mac_address', '')}",
                raw_evidence_ref=item["ip_address"],
                why_this_matters="A missing device can indicate expected shutdown, relocation, or an outage.",
                false_positive_notes="Laptops, printers, and phones often disappear normally.",
                recommended_next_steps="Check with the device owner or recent maintenance records.",
                what_can_go_wrong="Assuming a missing device is compromised can send effort in the wrong direction.",
            )
        )
    for item in comparison.gateway_changed:
        findings.append(
            make_finding(
                id="network-gateway-change",
                category="Network Discovery",
                title="Gateway changed since previous baseline",
                severity="medium",
                description="The gateway observed for this subnet differs from the previous baseline.",
                evidence=item["current_gateway"],
                command_used="netstat -rn / ifconfig",
                remediation_suggestion="Verify whether the gateway change was planned, such as after a router swap or network migration.",
                warning="Gateway changes can be normal, but they should match network maintenance records.",
                evidence_summary=f"previous={item['previous_gateway']} current={item['current_gateway']}",
                raw_evidence_ref="gateway-change",
                why_this_matters="Gateway changes can affect traffic flow, trust assumptions, and how discovery results are interpreted.",
                false_positive_notes="Maintenance, failover, or DHCP reconfiguration can cause this.",
                recommended_next_steps="Check network change records or router inventory for the new gateway.",
                what_can_go_wrong="Treating a planned gateway migration as suspicious can waste time.",
                business_impact="Gateway changes can affect connectivity for shared services and business workflows across the subnet.",
                local_network_impact="The gateway is central to local routing, so a change can affect all nearby devices on the segment.",
            )
        )
    for host in hosts:
        if host.hostname and re.search(r"(admin|default|test|unknown|desktop|laptop)", host.hostname, flags=re.IGNORECASE):
            findings.append(
                make_finding(
                    id=f"network-hostname-{host.ip_address}",
                    category="Network Discovery",
                    title="Unusual hostname observed",
                    severity="low",
                    description="The discovered hostname contains a pattern that may deserve manual review.",
                    evidence=host.hostname,
                    command_used="arp -a / ping sweep",
                    remediation_suggestion="Compare the hostname to asset inventory and user reports.",
                    warning="Unusual does not mean malicious.",
                    evidence_summary=f"{host.ip_address} hostname={host.hostname}",
                    raw_evidence_ref=host.ip_address,
                    why_this_matters="Unexpected names can help spot untracked lab systems or renamed devices.",
                    false_positive_notes="User-assigned hostnames are often informal.",
                    recommended_next_steps="Verify the device owner and whether the naming convention is expected.",
                    what_can_go_wrong="Escalating based on hostname alone can create noise.",
                )
            )
    return findings
