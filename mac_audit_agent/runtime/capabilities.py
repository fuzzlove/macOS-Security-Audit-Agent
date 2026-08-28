from __future__ import annotations

import importlib.util
import shutil
from dataclasses import asdict, dataclass
from typing import Optional

from .detector import PythonRuntimeInfo, detect_python_runtime
from .fallbacks import FALLBACKS


@dataclass(frozen=True)
class Capability:
    capability_id: str; display_name: str; required_modules: tuple[str, ...] = (); optional_modules: tuple[str, ...] = (); external_commands: tuple[str, ...] = (); fallback_available: bool = False; fallback_description: str = ""; install_extra: str = ""; status: str = "available"; reason: str = ""; user_message: str = ""; developer_message: str = ""
    def to_dict(self) -> dict: return asdict(self)


CAPABILITY_SPECS = {
    "core_cli": ("Core CLI", (), (), (), "core"), "doctor": ("Environment Doctor", (), (), (), "core"), "sqlite_storage": ("SQLite Storage", ("sqlite3",), (), (), "core"),
    "integrity_hashing": ("Integrity Hash Verification", ("hashlib",), (), (), "core"), "integrity_signature_verify": ("Integrity Signature Verification", (), ("cryptography",), ("openssl",), "crypto"), "integrity_signature_sign": ("Integrity Manifest Signing", (), ("cryptography",), ("openssl",), "crypto"),
    "gui": ("Graphical Interface", ("PySide6",), (), (), "gui"), "user_notifier": ("User Notifier", ("PySide6",), (), (), "gui"), "active_protection_install": ("Active Protection Install", ("sqlite3",), (), ("launchctl",), "core"), "active_protection_repair": ("Active Protection Repair", ("sqlite3",), (), ("launchctl",), "core"),
    "anti_ransomware_monitor": ("Anti-Ransomware Monitor", ("sqlite3",), (), (), "core"), "anti_ransomware_containment": ("Anti-Ransomware Containment", ("sqlite3",), (), (), "core"),
    "network_scan_basic": ("Basic Network Scan", (), (), ("lsof", "netstat"), "network"), "network_scan_enhanced": ("Enhanced Network Scan", (), (), ("nmap",), "network"), "process_metadata": ("Process Metadata", (), ("psutil",), ("ps",), "network"), "apple_security_guidance": ("Apple Security Guidance", (), ("requests",), (), "network"),
    "html_export": ("HTML Export", (), (), (), "core"), "json_export": ("JSON Export", (), (), (), "core"), "csv_export": ("CSV Export", (), (), (), "core"), "pdf_export": ("PDF Export", (), ("reportlab",), (), "exports"), "docx_export": ("Word Export", (), ("docx",), (), "exports"), "xlsx_export": ("Excel Export", (), ("openpyxl",), (), "exports"), "chart_rendering": ("Chart Rendering", (), ("matplotlib",), (), "exports"),
    "rootkit_visibility_review": ("Rootkit Visibility Review", (), (), ("lsof", "launchctl"), "core"), "packet_capture": ("Packet Capture", (), ("scapy",), (), "network"), "os_notifications": ("macOS Notifications", (), ("AppKit",), (), "gui"),
    "apple_exposure": ("Apple Exposure Guidance", (), ("requests", "httpx"), (), "network"), "persistence_review": ("Persistence Review", (), (), ("launchctl",), "core"),
}


def _module(name: str) -> bool:
    try: return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError): return False


class CapabilityRegistry:
    def __init__(self, runtime: Optional[PythonRuntimeInfo] = None) -> None: self.runtime = runtime or detect_python_runtime()
    def evaluate(self, capability_id: str) -> Capability:
        display, required, optional, commands, extra = CAPABILITY_SPECS[capability_id]
        missing_required = [name for name in required if not _module(name)]
        missing_optional = [name for name in optional if not _module(name)]
        missing_commands = [name for name in commands if shutil.which(name) is None]
        if capability_id in {"gui", "user_notifier"} and not self.runtime.gui_allowed:
            return Capability(capability_id, display, required, optional, commands, True, "Headless commands remain available.", extra, "blocked", "Current runtime tier does not allow GUI.", self.runtime.recommended_action, "GUI runtime policy blocked the capability.")
        if capability_id not in {"doctor"} and not self.runtime.headless_allowed and not self.runtime.gui_allowed:
            return Capability(capability_id, display, required, optional, commands, capability_id in {"core_cli", "integrity_hashing"}, "Run the environment doctor and select a supported interpreter.", extra, "blocked", "Current runtime tier is doctor-only.", self.runtime.recommended_action, "Tier C permits doctor/bootstrap only.")
        missing = missing_required or missing_optional or missing_commands
        fallback = next((FALLBACKS.get(name) for name in [*missing_required, *missing_optional, *missing_commands] if FALLBACKS.get(name)), None)
        if missing_required: status = "unavailable"
        elif missing: status = "degraded" if fallback and fallback.fallback_available else "unavailable"
        else: status = "available"
        reason = "Missing: " + ", ".join(missing) if missing else "All capability requirements are available."
        return Capability(capability_id, display, required, optional, commands, bool(fallback and fallback.fallback_available), fallback.fallback_description if fallback else "", extra, status, reason, fallback.user_message if fallback else "Available.", f"required={required}; optional={optional}; commands={commands}")
    def all(self) -> dict[str, Capability]: return {key: self.evaluate(key) for key in CAPABILITY_SPECS}
    def summary(self) -> dict: return {key: value.to_dict() for key, value in self.all().items()}


__all__ = ["Capability", "CapabilityRegistry", "CAPABILITY_SPECS"]
